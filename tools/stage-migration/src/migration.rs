//! One whole migration as the app runs it, timed per step.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use di_migration_client::{
    ClientError, MigrationApiClient,
    sealing::{EnclaveVerifier, MigrationResponseOpener},
};
use di_migration_primitives::{
    JobId, Status,
    app_api::{InitMigrationResponse, MigrationStatus, codes},
};
use zeroize::Zeroizing;

use crate::{
    report::{JobReport, Phase},
    user::{OwnershipProof, StageUser},
};

/// How often a running migration is polled.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Polling continues this long past the job's deadline, for the API to report the timeout.
const DEADLINE_GRACE: Duration = Duration::from_secs(30);

/// A migration step that failed, with what the API or client reported.
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    #[error("ownership proof failed: {0:#}")]
    Proof(#[source] anyhow::Error),
    #[error("{step} failed: {source}")]
    Client {
        step: &'static str,
        #[source]
        source: ClientError,
    },
    #[error("migration failed: {0}")]
    Failed(&'static str),
    #[error("the API still reports the job running past its deadline")]
    Overdue,
    #[error("the API reported the job migrated without {0}")]
    Incomplete(&'static str),
}

impl MigrationError {
    fn client(step: &'static str) -> impl FnOnce(ClientError) -> Self {
        move |source| Self::Client { step, source }
    }

    /// The API refused the job because the `sub` still holds an active one.
    pub fn is_migration_in_progress(&self) -> bool {
        matches!(self, Self::Client { source, .. } if source.reason() == codes::MIGRATION_IN_PROGRESS)
    }

    /// A short machine-readable cause, for grouping failures.
    pub fn reason(&self) -> String {
        match self {
            Self::Proof(_) => "proof".into(),
            Self::Client { step, source } => format!("{step}:{}", source.reason()),
            Self::Failed(reason) => format!("failed:{reason}"),
            Self::Overdue => "overdue".into(),
            Self::Incomplete(what) => format!("incomplete:{what}"),
        }
    }
}

/// The migration API and everything shared by every job.
pub struct Stage {
    pub client: MigrationApiClient,
    pub verifier: EnclaveVerifier,
    /// Recipient of the migrated PCP; the results are discarded, so one key serves all jobs.
    pub device_public_key: String,
    pub at_capacity_backoff_secs: u64,
}

struct Migrated {
    job_id: JobId,
    download_url: String,
}

impl Stage {
    /// Migrates `user`'s PCP and acknowledges the download, returning the unsealed result.
    pub async fn run_job(&self, user: &StageUser) -> (JobReport, Option<Zeroizing<Vec<u8>>>) {
        let mut report = JobReport::new(user.sub.clone());
        let started = Instant::now();
        let result = self.migrate(user, &mut report).await;
        report.total = started.elapsed();
        match result {
            Ok(migrated) => (report, Some(migrated)),
            Err(error) => {
                report.outcome = Err(error);
                (report, None)
            }
        }
    }

    async fn migrate(
        &self,
        user: &StageUser,
        report: &mut JobReport,
    ) -> Result<Zeroizing<Vec<u8>>, MigrationError> {
        let proof = report
            .time(Phase::Proof, async {
                user.ownership_proof().await.map_err(MigrationError::Proof)
            })
            .await?;
        let response = self.admit(user, &proof, report).await?;
        let opener = report
            .time(Phase::SealUpload, self.seal_and_upload(user, &response))
            .await?;
        report
            .time(Phase::Migrate, async {
                self.client
                    .migrate(user.device.integrity_token(), &user.device, &user.sub)
                    .await
                    .map(|_| ())
                    .map_err(MigrationError::client("migrate"))
            })
            .await?;
        let migrated = report.time(Phase::Wait, self.wait(user)).await?;
        let pcp = report
            .time(Phase::Download, async {
                self.client
                    .fetch_pcp(&migrated.download_url, opener.into_secret_bytes())
                    .await
                    .map_err(MigrationError::client("download"))
            })
            .await?;
        report
            .time(Phase::Acknowledge, async {
                self.client
                    .acknowledge(
                        user.device.integrity_token(),
                        &user.device,
                        &user.sub,
                        &migrated.job_id,
                    )
                    .await
                    .map_err(MigrationError::client("acknowledge"))
            })
            .await?;
        Ok(pcp)
    }

    /// Inits the migration, backing off while the fleet is at capacity.
    async fn admit(
        &self,
        user: &StageUser,
        proof: &OwnershipProof,
        report: &mut JobReport,
    ) -> Result<InitMigrationResponse, MigrationError> {
        let started = Instant::now();
        loop {
            let attempt = Instant::now();
            let result = self
                .client
                .init_migration(
                    user.device.integrity_token(),
                    &user.device,
                    &user.sub,
                    &proof.proof,
                    &proof.challenge_id,
                )
                .await;
            match result {
                Ok(response) => {
                    report.record(Phase::AdmissionWait, attempt.duration_since(started));
                    report.record(Phase::Init, attempt.elapsed());
                    return Ok(response);
                }
                Err(error) if error.reason() == codes::AT_CAPACITY => {
                    report.at_capacity += 1;
                    let backoff = self.at_capacity_backoff_secs;
                    let jitter = fastrand::u64(..=backoff);
                    tokio::time::sleep(Duration::from_secs(backoff + jitter)).await;
                }
                Err(error) => return Err(MigrationError::client("init-migration")(error)),
            }
        }
    }

    async fn seal_and_upload(
        &self,
        user: &StageUser,
        response: &InitMigrationResponse,
    ) -> Result<MigrationResponseOpener, MigrationError> {
        let (blob, opener) = self
            .verifier
            .attested_channel(response)
            .and_then(|channel| channel.seal(&user.pcp, &user.credential, &self.device_public_key))
            .map_err(|error| MigrationError::client("seal")(error.into()))?;
        self.client
            .upload_pcp(&response.upload_url, blob)
            .await
            .map_err(MigrationError::client("upload"))?;
        Ok(opener)
    }

    /// Polls until the job ends.
    async fn wait(&self, user: &StageUser) -> Result<Migrated, MigrationError> {
        loop {
            let status = self
                .client
                .migration_status(user.device.integrity_token(), &user.device, &user.sub)
                .await
                .map_err(MigrationError::client("status"))?;
            match status.status {
                Status::Migrated => return migrated(status),
                Status::Failed => {
                    return Err(MigrationError::Failed(
                        status.reason.map_or("unknown", |reason| reason.as_str()),
                    ));
                }
                Status::Created | Status::Migrating => {}
            }
            if let Some(deadline) = status.deadline
                && unix_now() > deadline + DEADLINE_GRACE.as_secs()
            {
                return Err(MigrationError::Overdue);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
}

fn migrated(status: MigrationStatus) -> Result<Migrated, MigrationError> {
    Ok(Migrated {
        job_id: status
            .job_id
            .ok_or(MigrationError::Incomplete("a job id"))?,
        download_url: status
            .download_url
            .ok_or(MigrationError::Incomplete("a download URL"))?,
    })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}
