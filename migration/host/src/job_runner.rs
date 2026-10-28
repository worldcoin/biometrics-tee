//! The single job runner: one job at a time from fetch to recorded outcome.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use di_migration_enclave_primitives::{self as enclave_primitives, MigrateRequest};
use di_migration_primitives::{Reason, host_api::JobRequest};
use telemetry_batteries::reexports::metrics;

use crate::{
    enclave::{self, EnclaveClient},
    queue::JobQueue,
    store::{BlobStore, JobStore, StoreError},
};

/// Everything a job touches.
pub struct JobRunner {
    queue: Arc<JobQueue>,
    enclave_client: Arc<dyn EnclaveClient>,
    blob_store: Arc<dyn BlobStore>,
    job_store: Arc<dyn JobStore>,
}

impl JobRunner {
    /// Creates a job runner draining `queue`.
    #[must_use]
    pub fn new(
        queue: Arc<JobQueue>,
        enclave_client: Arc<dyn EnclaveClient>,
        blob_store: Arc<dyn BlobStore>,
        job_store: Arc<dyn JobStore>,
    ) -> Self {
        Self {
            queue,
            enclave_client,
            blob_store,
            job_store,
        }
    }

    /// Runs jobs until the process stops; the enclave serves one migration at a time.
    pub async fn run(self) {
        loop {
            let job = self.queue.next().await;
            self.handle(&job).await;
            self.queue.finish(&job.job_id);
        }
    }

    /// Runs `job` and records its outcome. A job whose deadline passed while it waited already
    /// reads as `timeout`, so it is skipped rather than spending enclave time.
    pub async fn handle(&self, job: &JobRequest) {
        if unix_now() > job.deadline {
            metrics::counter!("migration.host.job_failures", "reason" => Reason::Timeout.as_str())
                .increment(1);
            tracing::warn!(job_id = %job.job_id, "job passed its deadline in the queue; skipped");
            return;
        }
        let recorded = match self.migrate(job).await {
            Ok(result_key) => self.job_store.mark_migrated(job, &result_key).await,
            Err((reason, result_key)) => {
                // Count the observed failure even if persisting the outcome fails.
                metrics::counter!("migration.host.job_failures", "reason" => reason.as_str())
                    .increment(1);
                self.job_store
                    .mark_failed(job, reason, result_key.as_deref())
                    .await
            }
        };

        match recorded {
            Ok(()) => {}
            Err(StoreError::NotMigrating) => tracing::warn!(
                job_id = %job.job_id,
                "job was resolved elsewhere first or passed its deadline; outcome not recorded"
            ),
            // The row stays `migrating` and reads as `timeout` once its deadline passes.
            Err(error) => tracing::error!(
                job_id = %job.job_id,
                %error,
                dependency = "dynamodb",
                "failed to record the job outcome"
            ),
        }
    }

    async fn migrate(&self, job: &JobRequest) -> Result<String, (Reason, Option<String>)> {
        let blob = self
            .blob_store
            .get_pcp(&job.object_key)
            .await
            .map_err(|error| {
                tracing::error!(job_id = %job.job_id, %error, dependency = "s3", "failed to read the sealed PCP");
                (Reason::S3Error, None)
            })?;

        let failure_reason = |error: &enclave::Error| {
            let reason = match error {
                enclave::Error::Operation(error) => operation_reason(*error),
                enclave::Error::Migration(error) => operation_reason(error.error),
                enclave::Error::Timeout => Reason::Timeout,
                enclave::Error::Transport(_) => Reason::Transport,
            };
            if reason == Reason::EnclaveChanged {
                tracing::warn!(job_id = %job.job_id, ?error, dependency = "enclave", "migration failed");
            } else {
                tracing::error!(job_id = %job.job_id, ?error, dependency = "enclave", "migration failed");
            }
            reason
        };

        let migration = self
            .enclave_client
            .migrate(MigrateRequest {
                blob,
                sub: job.sub.clone(),
            })
            .await;
        let (pcp, debug_report) = match migration {
            Ok(response) => (Ok(response.pcp), response.debug_report),
            Err(error) => {
                let reason = failure_reason(&error);
                let debug_report = match error {
                    enclave::Error::Migration(error) => error.debug_report,
                    _ => None,
                };
                (Err(reason), debug_report)
            }
        };

        let debug_report_key = if let Some(report) = debug_report {
            if report.len() < enclave_primitives::MIGRATION_DIAGNOSTIC_OVERHEAD_BYTES
                || report.len() > enclave_primitives::MAX_SEALED_MIGRATION_DIAGNOSTIC_BYTES
            {
                tracing::error!(job_id = %job.job_id, diagnostic_bytes = report.len(), "enclave returned an invalid diagnostic response");
                return Err((Reason::InvalidDebugReport, None));
            }
            match self.blob_store.put_debug_report(&job.job_id, report).await {
                Ok(key) => Some(key),
                Err(error) => {
                    tracing::warn!(job_id = %job.job_id, %error, dependency = "s3", operation = "put_debug_report", "failed to write the encrypted diagnostic; preserving migration outcome");
                    metrics::counter!("migration.host.debug_report_failures", "reason" => "storage").increment(1);
                    None
                }
            }
        } else {
            None
        };
        let pcp = pcp.map_err(|reason| (reason, debug_report_key))?;
        if pcp.is_empty() {
            tracing::error!(job_id = %job.job_id, "enclave returned no result artifact");
            return Err((Reason::EnclaveError, None));
        }

        self.blob_store
            .put_result(&job.job_id, pcp)
            .await
            .map_err(|error| {
                tracing::error!(job_id = %job.job_id, %error, dependency = "s3", "failed to write the result");
                (Reason::S3Error, None)
            })
    }
}

const fn operation_reason(error: enclave_primitives::Error) -> Reason {
    use enclave_primitives::Error;

    match error {
        Error::InvalidInput => Reason::InvalidInput,
        // The enclave restarted after dispatch, so the PCP is sealed to a dead key.
        Error::RequestNotOpened => Reason::EnclaveChanged,
        Error::MigrationTaskCancelled => Reason::MigrationTaskCancelled,
        Error::MigrationDiagnosticSealingFailed => Reason::MigrationDiagnosticSealingFailed,
        Error::InvalidSystemTime => Reason::InvalidSystemTime,
        Error::PcpRecipientKeyGenerationFailed => Reason::PcpRecipientKeyGenerationFailed,
        Error::ManifestSignerUnavailable => Reason::ManifestSignerUnavailable,
        Error::PcpResponseSealingFailed => Reason::PcpResponseSealingFailed,
        Error::BiometricPipelineFailed => Reason::BiometricPipelineFailed,
        Error::BiometricInvalidRequest => Reason::BiometricInvalidRequest,
        Error::BiometricInvalidImage => Reason::BiometricInvalidImage,
        Error::BiometricQualityRejected => Reason::BiometricQualityRejected,
        Error::BiometricSpoofDetected => Reason::BiometricSpoofDetected,
        Error::IncompleteBiometricPipelineResult => Reason::IncompleteBiometricPipelineResult,
        Error::EmbeddingShareGenerationFailed => Reason::EmbeddingShareGenerationFailed,
        Error::PcpKeyDecryptionFailed => Reason::PcpKeyDecryptionFailed,
        Error::AttestationFailed => Reason::AttestationFailed,
        Error::ChannelKeyGenerationFailed => Reason::ChannelKeyGenerationFailed,
        Error::CredentialSubMismatch => Reason::CredentialSubMismatch,
        Error::CredentialDeserializationFailed => Reason::CredentialDeserializationFailed,
        Error::CredentialSignatureVerificationFailed => {
            Reason::CredentialSignatureVerificationFailed
        }
        Error::CredentialSignatureInvalid => Reason::CredentialSignatureInvalid,
        Error::CredentialClaimsMismatch => Reason::CredentialClaimsMismatch,
        Error::InvalidPcp => Reason::InvalidPcp,
        Error::FailedToBuildPcp => Reason::FailedToBuildPcp,
        Error::InvalidDevicePublicKeyEncoding => Reason::InvalidDevicePublicKeyEncoding,
        Error::Unknown => Reason::Unknown,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, sync::Arc};

    use di_migration_enclave_primitives as enclave_primitives;
    use di_migration_primitives::Reason;

    use super::{JobRunner, operation_reason};
    use crate::{
        enclave,
        queue::JobQueue,
        store::StoreError,
        test_support::{FailingEnclave, GatedEnclave, MemoryStore, Outcome, StubEnclave, job},
    };

    fn result_key(n: u64) -> String {
        di_migration_storage::schema::result_key(&job(n).job_id)
    }

    fn job_runner(enclave: Arc<dyn enclave::EnclaveClient>, store: &Arc<MemoryStore>) -> JobRunner {
        JobRunner::new(
            Arc::new(JobQueue::new(NonZeroUsize::new(4).expect("non-zero"))),
            enclave,
            store.clone(),
            store.clone(),
        )
    }

    #[tokio::test]
    async fn a_migrated_blob_is_stored_and_the_job_marked_migrated() {
        let store = Arc::new(MemoryStore::with_pcp(&job(1), b"sealed"));

        let enclave = Arc::new(StubEnclave::default());
        job_runner(enclave.clone(), &store).handle(&job(1)).await;

        let migrations = enclave.migrations.lock().expect("migrations lock");
        assert_eq!(migrations.len(), 1);
        drop(migrations);

        assert_eq!(
            store.result(&job(1).job_id).as_deref(),
            Some(b"sealed".as_slice())
        );
        assert_eq!(
            store.outcome(&job(1).job_id),
            Some(Outcome::Migrated(result_key(1)))
        );
    }

    #[tokio::test]
    async fn an_encrypted_diagnostic_is_stored_and_the_job_stays_failed() {
        let ciphertext = vec![7; 96];
        for fail_upload in [false, true] {
            let store = MemoryStore::with_pcp(&job(1), b"sealed");
            let store = Arc::new(if fail_upload {
                store.failing_debug_report_writes()
            } else {
                store
            });
            let enclave = FailingEnclave(enclave::Error::Migration(
                enclave_primitives::MigrateError {
                    error: enclave_primitives::Error::CredentialSignatureInvalid,
                    debug_report: Some(ciphertext.clone()),
                },
            ));
            job_runner(Arc::new(enclave), &store).handle(&job(1)).await;
            assert_eq!(
                store.outcome(&job(1).job_id),
                Some(Outcome::Failed(Reason::CredentialSignatureInvalid))
            );
            if fail_upload {
                assert!(store.error_key(&job(1).job_id).is_none());
                assert!(store.debug_report(&job(1).job_id).is_none());
            } else {
                assert_eq!(
                    store.error_key(&job(1).job_id),
                    Some(di_migration_storage::schema::debug_report_key(
                        &job(1).job_id
                    ))
                );
                assert_eq!(store.debug_report(&job(1).job_id), Some(ciphertext.clone()));
            }
            assert!(store.result(&job(1).job_id).is_none());
        }
    }

    #[tokio::test]
    async fn a_successful_migration_can_also_store_a_debug_report() {
        let store = Arc::new(MemoryStore::with_pcp(&job(1), b"sealed"));
        let enclave = StubEnclave {
            response: Some(enclave_primitives::MigrateResponse {
                pcp: b"migrated".to_vec(),
                debug_report: Some(vec![7; 96]),
            }),
            ..StubEnclave::default()
        };

        job_runner(Arc::new(enclave), &store).handle(&job(1)).await;

        assert_eq!(
            store.outcome(&job(1).job_id),
            Some(Outcome::Migrated(result_key(1)))
        );
        assert_eq!(store.result(&job(1).job_id), Some(b"migrated".to_vec()));
        assert_eq!(store.debug_report(&job(1).job_id), Some(vec![7; 96]));
    }

    #[tokio::test]
    async fn a_report_upload_failure_does_not_discard_a_successful_pcp() {
        let store =
            Arc::new(MemoryStore::with_pcp(&job(1), b"sealed").failing_debug_report_writes());
        let enclave = StubEnclave {
            response: Some(enclave_primitives::MigrateResponse {
                pcp: b"migrated".to_vec(),
                debug_report: Some(vec![7; 96]),
            }),
            ..StubEnclave::default()
        };

        job_runner(Arc::new(enclave), &store).handle(&job(1)).await;

        assert_eq!(
            store.outcome(&job(1).job_id),
            Some(Outcome::Migrated(result_key(1)))
        );
        assert_eq!(store.result(&job(1).job_id), Some(b"migrated".to_vec()));
        assert!(store.debug_report(&job(1).job_id).is_none());
    }

    #[tokio::test]
    async fn invalid_debug_report_sizes_are_rejected_on_success_and_failure() {
        for error in [
            None,
            Some(enclave_primitives::Error::BiometricPipelineFailed),
        ] {
            for size in [
                0,
                enclave_primitives::MIGRATION_DIAGNOSTIC_OVERHEAD_BYTES - 1,
                enclave_primitives::MAX_SEALED_MIGRATION_DIAGNOSTIC_BYTES + 1,
            ] {
                let store = Arc::new(MemoryStore::with_pcp(&job(1), b"sealed"));
                let enclave: Arc<dyn enclave::EnclaveClient> = match error {
                    Some(error) => Arc::new(FailingEnclave(enclave::Error::Migration(
                        enclave_primitives::MigrateError {
                            error,
                            debug_report: Some(vec![7; size]),
                        },
                    ))),
                    None => Arc::new(StubEnclave {
                        response: Some(enclave_primitives::MigrateResponse {
                            pcp: b"pcp".to_vec(),
                            debug_report: Some(vec![7; size]),
                        }),
                        ..StubEnclave::default()
                    }),
                };

                job_runner(enclave, &store).handle(&job(1)).await;

                assert_eq!(
                    store.outcome(&job(1).job_id),
                    Some(Outcome::Failed(Reason::InvalidDebugReport))
                );
                assert!(store.result(&job(1).job_id).is_none());
                assert!(store.debug_report(&job(1).job_id).is_none());
            }
        }
    }

    /// Pins each failure to the reason the app sees.
    #[tokio::test]
    async fn each_failure_is_recorded_with_its_reason() {
        let cases: Vec<(Arc<dyn enclave::EnclaveClient>, Arc<MemoryStore>, Reason)> = vec![
            (
                Arc::new(StubEnclave::default()),
                Arc::new(MemoryStore::default()),
                Reason::S3Error,
            ),
            (
                Arc::new(FailingEnclave(enclave::Error::Timeout)),
                Arc::new(MemoryStore::with_pcp(&job(1), b"sealed")),
                Reason::Timeout,
            ),
            (
                Arc::new(FailingEnclave(enclave::Error::Transport(
                    "refused".to_owned(),
                ))),
                Arc::new(MemoryStore::with_pcp(&job(1), b"sealed")),
                Reason::Transport,
            ),
            (
                Arc::new(FailingEnclave(enclave::Error::Operation(
                    enclave_primitives::Error::RequestNotOpened,
                ))),
                Arc::new(MemoryStore::with_pcp(&job(1), b"sealed")),
                Reason::EnclaveChanged,
            ),
            (
                Arc::new(FailingEnclave(enclave::Error::Operation(
                    enclave_primitives::Error::InvalidInput,
                ))),
                Arc::new(MemoryStore::with_pcp(&job(1), b"sealed")),
                Reason::InvalidInput,
            ),
            (
                Arc::new(FailingEnclave(enclave::Error::Migration(
                    enclave_primitives::Error::BiometricPipelineFailed.into(),
                ))),
                Arc::new(MemoryStore::with_pcp(&job(1), b"sealed")),
                Reason::BiometricPipelineFailed,
            ),
            (
                Arc::new(StubEnclave::default()),
                Arc::new(MemoryStore::with_pcp(&job(1), b"sealed").failing_writes()),
                Reason::S3Error,
            ),
        ];

        for (enclave, store, reason) in cases {
            job_runner(enclave, &store).handle(&job(1)).await;

            assert_eq!(store.outcome(&job(1).job_id), Some(Outcome::Failed(reason)));
        }
    }

    #[test]
    fn each_operation_failure_maps_to_its_reason() {
        macro_rules! same_reason {
            ($($variant:ident),+ $(,)?) => {
                $(assert_eq!(
                    operation_reason(enclave_primitives::Error::$variant),
                    Reason::$variant
                );)+
            };
        }

        same_reason!(
            InvalidInput,
            MigrationTaskCancelled,
            MigrationDiagnosticSealingFailed,
            InvalidSystemTime,
            PcpRecipientKeyGenerationFailed,
            ManifestSignerUnavailable,
            PcpResponseSealingFailed,
            BiometricPipelineFailed,
            BiometricInvalidRequest,
            BiometricInvalidImage,
            BiometricQualityRejected,
            BiometricSpoofDetected,
            IncompleteBiometricPipelineResult,
            EmbeddingShareGenerationFailed,
            PcpKeyDecryptionFailed,
            AttestationFailed,
            ChannelKeyGenerationFailed,
            CredentialSubMismatch,
            CredentialDeserializationFailed,
            CredentialSignatureVerificationFailed,
            CredentialSignatureInvalid,
            CredentialClaimsMismatch,
            InvalidPcp,
            FailedToBuildPcp,
            InvalidDevicePublicKeyEncoding,
            Unknown,
        );
        assert_eq!(
            operation_reason(enclave_primitives::Error::RequestNotOpened),
            Reason::EnclaveChanged
        );
    }

    /// A job that timed out first keeps its `failed` row; the late result is not recorded.
    /// A job that waited past its deadline is neither run nor recorded.
    #[tokio::test]
    async fn a_job_past_its_deadline_is_skipped() {
        let mut expired = job(1);
        expired.deadline = 1;
        let store = Arc::new(MemoryStore::with_pcp(&expired, b"sealed"));

        job_runner(Arc::new(StubEnclave::default()), &store)
            .handle(&expired)
            .await;

        // Running it would record an outcome either way.
        assert!(store.outcome(&expired.job_id).is_none());
    }

    #[tokio::test]
    async fn a_job_resolved_elsewhere_is_not_overwritten() {
        let store = Arc::new(MemoryStore::with_pcp(&job(1), b"sealed").resolved_elsewhere());

        job_runner(Arc::new(StubEnclave::default()), &store)
            .handle(&job(1))
            .await;

        assert_eq!(store.outcome(&job(1).job_id), None);
        assert_eq!(store.last_error(), Some(StoreError::NotMigrating));
    }

    #[tokio::test]
    async fn jobs_run_one_at_a_time_in_order() {
        let store = Arc::new(MemoryStore::with_pcp(&job(1), b"first").and_pcp(&job(2), b"second"));
        let (enclave, entered, release) = GatedEnclave::new();
        let queue = Arc::new(JobQueue::new(NonZeroUsize::new(4).expect("non-zero")));
        let runner = tokio::spawn(
            JobRunner::new(
                Arc::clone(&queue),
                Arc::new(enclave),
                store.clone(),
                store.clone(),
            )
            .run(),
        );

        queue.push(job(1)).expect("room");
        queue.push(job(2)).expect("room");

        entered.notified().await;
        assert_eq!(
            store.outcome(&job(1).job_id),
            None,
            "a is still in the enclave"
        );
        assert_eq!(store.outcome(&job(2).job_id), None, "b waits behind a");
        release.notify_one();

        entered.notified().await;
        assert_eq!(
            store.outcome(&job(1).job_id),
            Some(Outcome::Migrated(result_key(1)))
        );
        assert_eq!(
            store.outcome(&job(2).job_id),
            None,
            "b is in the enclave now"
        );
        release.notify_one();

        while store.outcome(&job(2).job_id).is_none() {
            tokio::task::yield_now().await;
        }
        assert_eq!(queue.queued(), 0);
        runner.abort();
    }
}
