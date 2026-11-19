//! Developer CLI for the migration API.

mod load;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use attested_request::{
    Platform,
    test_util::{SoftwareSigner, test_key},
};
use clap::{Args, Parser, Subcommand};
use di_migration_client::{
    ClientError, MigrationApiClient,
    sealing::{EnclaveVerifier, MigrationResponseOpener},
};
use di_migration_primitives::{
    JobId, Status,
    app_api::{InitMigrationResponse, MigrationStatus},
};
use pontifex::PcrConfig;
use reqwest::Url;
use zeroize::Zeroizing;

/// How often a running migration is polled.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Polling continues this long past the job's deadline, for the API to report the timeout.
const DEADLINE_GRACE: Duration = Duration::from_secs(30);

#[derive(Parser)]
#[command(name = "migration-cli", version, about)]
struct Cli {
    /// Base URL of the migration API.
    #[arg(
        long,
        env = "API_URL",
        default_value = "http://127.0.0.1:8080",
        global = true
    )]
    api_url: Url,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Starts a migration and prints the enclave id, attestation and upload URL.
    InitMigration(InitArgs),
    /// Runs a whole migration as the app does: verifies the enclave, seals and uploads the PCP,
    /// waits for the job, and unseals the migrated PCP into `--out`.
    Migrate {
        #[command(flatten)]
        init: InitArgs,

        #[command(flatten)]
        seal: SealArgs,

        /// Where the migrated PCP is written, readable by the owner only.
        #[arg(long)]
        out: PathBuf,
    },
    /// Runs many whole migrations of one PCP, each under a fresh random `sub`, and reports
    /// per-phase timings. Needs a proof verifier that accepts the proof for any `sub`.
    Load(load::LoadArgs),
}

/// How the device authenticates and proves ownership.
#[derive(Args, Clone)]
struct DeviceArgs {
    /// Attestation Gateway integrity token (JWT) whose `cnf.jwk` matches the signer.
    #[arg(long, env = "INTEGRITY_TOKEN")]
    integrity_token: String,

    /// Seed for a local software signer whose public key must match `cnf.jwk` in the token.
    ///
    /// Only for environments whose proxy trusts a test JWKS (as stage does). The real Attestation
    /// Gateway will never attest a key derived from a public seed.
    #[arg(long, env = "DEVICE_SIGNER_SEED", default_value = "migration-cli")]
    device_signer_seed: String,

    /// Attested key thumbprint header for environments without an auth proxy (tests, local).
    ///
    /// In production the proxy sets `x-attested-key-thumbprint` from the request signature.
    #[arg(long, env = "DEVICE_KEY_THUMBPRINT")]
    attested_key_thumbprint: Option<String>,

    /// Standard base64 ownership proof.
    #[arg(long, env = "PROOF")]
    proof: String,

    /// Challenge id the ownership proof was built for.
    #[arg(long, env = "CHALLENGE_ID")]
    challenge_id: String,
}

#[derive(Args)]
struct InitArgs {
    #[command(flatten)]
    device: DeviceArgs,

    /// Subject of the user being migrated.
    #[arg(long, env = "SUB")]
    sub: String,
}

/// What is sealed to the enclave, and which enclaves to trust.
#[derive(Args)]
struct SealArgs {
    /// The PCP to migrate.
    #[arg(long)]
    pcp: PathBuf,

    /// PCR JSON of the enclave build to trust, as `scripts/build-enclaves.sh` writes it.
    #[arg(
        long,
        env = "ENCLAVE_PCRS",
        required_unless_present = "insecure_skip_measurements"
    )]
    pcrs: Option<PathBuf>,

    /// Trusts any genuine Nitro enclave whatever it runs; only for debug-mode enclaves.
    #[arg(long, conflicts_with = "pcrs")]
    insecure_skip_measurements: bool,

    /// Self-custody credential to seal the PCP with.
    #[arg(long, env = "CREDENTIAL")]
    credential: String,

    /// Standard-Base64, 32-byte Curve25519 recipient key sealed with the PCP.
    #[arg(long, env = "DEVICE_PUBLIC_KEY")]
    device_public_key: String,
}

/// A device talking to the API: the client, its signer and its ownership proof.
struct Device {
    client: MigrationApiClient,
    signer: Arc<SoftwareSigner>,
    integrity_token: String,
    proof: String,
    challenge_id: String,
}

/// The loaded PCP and how to seal it.
struct Sealing {
    verifier: EnclaveVerifier,
    pcp: Vec<u8>,
    credential: String,
    device_public_key: String,
}

/// A migration step that failed, with what the API or client reported.
#[derive(Debug, thiserror::Error)]
enum MigrationError {
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

    /// A short machine-readable cause, for grouping failures.
    fn reason(&self) -> String {
        match self {
            Self::Client { step, source } => format!("{step}:{}", source.reason()),
            Self::Failed(reason) => format!("failed:{reason}"),
            Self::Overdue => "overdue".into(),
            Self::Incomplete(what) => format!("incomplete:{what}"),
        }
    }
}

/// A migrated job, ready to download and acknowledge.
struct Migrated {
    job_id: JobId,
    download_url: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::InitMigration(init) => {
            let device = Device::new(&cli.api_url, &init.device)?;
            let response = device
                .init_migration(&init.sub)
                .await
                .map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&response).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Command::Migrate { init, seal, out } => {
            let device = Device::new(&cli.api_url, &init.device)?;
            let sealing = Sealing::load(&seal)?;
            let migrated = migrate_once(&device, &sealing, &init.sub)
                .await
                .map_err(|error| error.to_string())?;
            write_private(&out, &migrated)?;
            eprintln!("migrated PCP written to {}", out.display());
            Ok(())
        }
        Command::Load(args) => load::run(&cli.api_url, args).await,
    }
}

/// Runs one migration end to end, returning the unsealed migrated PCP.
async fn migrate_once(
    device: &Device,
    sealing: &Sealing,
    sub: &str,
) -> Result<Zeroizing<Vec<u8>>, MigrationError> {
    let response = device.init_migration(sub).await?;
    let enclave_id = response.enclave_id.as_str().to_owned();
    let (blob, opener) = sealing.seal(&response)?;
    eprintln!("enclave {enclave_id} verified");
    device.upload(&response.upload_url, blob).await?;
    device.migrate(sub).await?;
    eprintln!("migration started on enclave {enclave_id}");
    let migrated = device.wait(sub).await?;
    device.download(&migrated.download_url, opener).await
}

impl Device {
    fn new(api_url: &Url, args: &DeviceArgs) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(300))
            .build()
            .map_err(|error| format!("failed to build the HTTP client: {error}"))?;
        let mut client = MigrationApiClient::with_http_client(api_url, http)
            .map_err(|error| error.to_string())?;
        if let Some(key) = &args.attested_key_thumbprint {
            client = client.with_attested_key_thumbprint(key);
        }
        Ok(Self {
            client,
            signer: Arc::new(SoftwareSigner::new(
                test_key(&args.device_signer_seed),
                Platform::Android,
            )),
            integrity_token: args.integrity_token.clone(),
            proof: args.proof.clone(),
            challenge_id: args.challenge_id.clone(),
        })
    }

    async fn init_migration(&self, sub: &str) -> Result<InitMigrationResponse, MigrationError> {
        self.client
            .init_migration(
                &self.integrity_token,
                &self.signer,
                sub,
                &self.proof,
                &self.challenge_id,
            )
            .await
            .map_err(MigrationError::client("init-migration"))
    }

    async fn upload(&self, upload_url: &str, blob: Vec<u8>) -> Result<(), MigrationError> {
        self.client
            .upload_pcp(upload_url, blob)
            .await
            .map_err(MigrationError::client("upload"))
    }

    async fn migrate(&self, sub: &str) -> Result<(), MigrationError> {
        self.client
            .migrate(&self.integrity_token, &self.signer, sub)
            .await
            .map(|_| ())
            .map_err(MigrationError::client("migrate"))
    }

    /// Polls until the job ends.
    async fn wait(&self, sub: &str) -> Result<Migrated, MigrationError> {
        loop {
            let status = self.status(sub).await?;
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

    async fn status(&self, sub: &str) -> Result<MigrationStatus, MigrationError> {
        self.client
            .migration_status(&self.integrity_token, &self.signer, sub)
            .await
            .map_err(MigrationError::client("status"))
    }

    async fn download(
        &self,
        download_url: &str,
        opener: MigrationResponseOpener,
    ) -> Result<Zeroizing<Vec<u8>>, MigrationError> {
        self.client
            .fetch_pcp(download_url, opener.into_secret_bytes())
            .await
            .map_err(MigrationError::client("download"))
    }

    async fn acknowledge(&self, sub: &str, job_id: &JobId) -> Result<(), MigrationError> {
        self.client
            .acknowledge(&self.integrity_token, &self.signer, sub, job_id)
            .await
            .map_err(MigrationError::client("acknowledge"))
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

impl Sealing {
    fn load(args: &SealArgs) -> Result<Self, String> {
        let verifier = match &args.pcrs {
            Some(path) => EnclaveVerifier::new(vec![read_pcrs(path)?]),
            None if args.insecure_skip_measurements => {
                EnclaveVerifier::dangerously_skip_measurements()
            }
            None => return Err("--pcrs or --insecure-skip-measurements is required".into()),
        };
        let pcp = std::fs::read(&args.pcp)
            .map_err(|error| format!("failed to read {}: {error}", args.pcp.display()))?;
        Ok(Self {
            verifier,
            pcp,
            credential: args.credential.clone(),
            device_public_key: args.device_public_key.clone(),
        })
    }

    /// Verifies the enclave in `response` and seals the PCP to it.
    fn seal(
        &self,
        response: &InitMigrationResponse,
    ) -> Result<(Vec<u8>, MigrationResponseOpener), MigrationError> {
        self.verifier
            .attested_channel(response)
            .and_then(|channel| channel.seal(&self.pcp, &self.credential, &self.device_public_key))
            .map_err(|error| MigrationError::client("seal")(error.into()))
    }
}

/// PCR0-2 from the JSON `scripts/build-enclaves.sh` writes, as lower-case hex.
fn read_pcrs(path: &Path) -> Result<PcrConfig, String> {
    let raw = std::fs::read(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let pcrs: HashMap<String, String> = serde_json::from_slice(&raw)
        .map_err(|error| format!("{} is not PCR JSON: {error}", path.display()))?;
    let pcr = |index: u32| -> Result<Vec<u8>, String> {
        let key = format!("PCR{index}");
        let value = pcrs
            .get(&key)
            .ok_or_else(|| format!("{} has no {key}", path.display()))?;
        hex::decode(value).map_err(|_| format!("{key} in {} is not hex", path.display()))
    };

    let image: [u8; 48] = pcr(0)?
        .try_into()
        .map_err(|_| format!("PCR0 in {} is not 48 bytes", path.display()))?;
    Ok(PcrConfig::new(image)
        .with_pcr(1, pcr(1)?)
        .with_pcr(2, pcr(2)?))
}

/// Writes `bytes` to a new file only its owner can read.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _};

    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .map_err(|error| format!("failed to write {}: {error}", path.display()))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Command, read_pcrs};

    #[test]
    fn init_does_not_require_a_recipient_key() {
        let cli = Cli::try_parse_from([
            "migration-cli",
            "init-migration",
            "--integrity-token",
            "token",
            "--sub",
            "sub",
            "--proof",
            "proof",
            "--challenge-id",
            "challenge",
        ])
        .expect("init needs no recipient key");
        assert!(matches!(cli.command, Command::InitMigration(_)));
    }

    fn pcrs_file(json: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(file.path(), json).expect("should write");
        file
    }

    #[test]
    fn build_pcrs_are_read() {
        let pcr = "ab".repeat(48);
        let file = pcrs_file(&format!(
            r#"{{"HashAlgorithm":"Sha384 {{ ... }}","PCR0":"{pcr}","PCR1":"{pcr}","PCR2":"{pcr}"}}"#
        ));

        read_pcrs(file.path()).expect("valid PCRs");
    }

    #[test]
    fn a_missing_or_short_pcr_is_rejected() {
        let pcr = "ab".repeat(48);
        for json in [
            format!(r#"{{"PCR0":"{pcr}","PCR1":"{pcr}"}}"#),
            format!(r#"{{"PCR0":"abcd","PCR1":"{pcr}","PCR2":"{pcr}"}}"#),
            format!(r#"{{"PCR0":"zz","PCR1":"{pcr}","PCR2":"{pcr}"}}"#),
        ] {
            assert!(read_pcrs(pcrs_file(&json).path()).is_err(), "{json}");
        }
    }
}
