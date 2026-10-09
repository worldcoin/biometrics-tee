//! Developer CLI for the migration API.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use attested_request::{
    Platform,
    test_util::{SoftwareSigner, test_key},
};
use clap::{Args, Parser, Subcommand};
use di_migration_client::{
    MigrationApiClient, StartMigration,
    sealing::{EnclaveVerifier, PcpOpener},
};
use di_migration_primitives::Status;
use pontifex::PcrConfig;
use reqwest::Url;

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
    /// waits for the job, and opens the migrated PCP into `--out`.
    Migrate {
        #[command(flatten)]
        init: InitArgs,

        /// The PCP to migrate.
        #[arg(long)]
        pcp: PathBuf,

        /// Where the migrated PCP is written, readable by the owner only.
        #[arg(long)]
        out: PathBuf,

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
    },
}

#[derive(Args)]
struct InitArgs {
    /// Attestation Gateway integrity token (JWT) whose `cnf.jwk` matches the signer.
    #[arg(long, env = "INTEGRITY_TOKEN")]
    integrity_token: String,

    /// Seed for a local software signer whose public key must match `cnf.jwk` in the token.
    ///
    /// Only for environments whose proxy trusts a test JWKS (as stage does). The real Attestation
    /// Gateway will never attest a key derived from a public seed.
    #[arg(long, env = "DEVICE_SIGNER_SEED", default_value = "migration-cli")]
    device_signer_seed: String,

    /// The device public key; in production the auth proxy sets it after verifying the device.
    #[arg(long, env = "DEVICE_PUBLIC_KEY")]
    device_public_key: String,

    /// Subject of the user being migrated.
    #[arg(long, env = "SUB")]
    sub: String,

    /// Standard base64 ownership proof.
    #[arg(long, env = "PROOF")]
    proof: String,

    /// Challenge id the ownership proof was built for.
    #[arg(long, env = "CHALLENGE_ID")]
    challenge_id: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let client = match MigrationApiClient::new(&cli.api_url) {
        Ok(client) => client,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };

    match run(&client, cli.command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(client: &MigrationApiClient, command: Command) -> Result<(), String> {
    match command {
        Command::InitMigration(init) => {
            let response = init_migration(client, &init).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&response).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Command::Migrate {
            init,
            pcp,
            out,
            pcrs,
            insecure_skip_measurements,
            credential,
        } => {
            let verifier = match pcrs {
                Some(path) => EnclaveVerifier::new(vec![read_pcrs(&path)?]),
                None if insecure_skip_measurements => {
                    EnclaveVerifier::dangerously_skip_measurements()
                }
                None => return Err("--pcrs or --insecure-skip-measurements is required".into()),
            };
            let pcp = std::fs::read(&pcp)
                .map_err(|error| format!("failed to read {}: {error}", pcp.display()))?;

            let opener = start(client, &init, &verifier, &pcp, &credential).await?;
            let download_url = wait(client, &init).await?;
            let blob = client
                .download_pcp(&download_url)
                .await
                .map_err(|error| format!("download failed: {error}"))?;
            let migrated = opener.open(&blob).map_err(|error| error.to_string())?;

            write_private(&out, &migrated.0)?;
            eprintln!("migrated PCP written to {}", out.display());
            Ok(())
        }
    }
}

async fn init_migration(
    client: &MigrationApiClient,
    init: &InitArgs,
) -> Result<di_migration_primitives::app_api::InitMigrationResponse, String> {
    let signer = SoftwareSigner::new(test_key(&init.device_signer_seed), Platform::Android);
    client
        .init_migration(
            &init.integrity_token,
            &signer,
            &init.device_public_key,
            &init.sub,
            &init.proof,
            &init.challenge_id,
        )
        .await
        .map_err(|error| format!("init-migration failed: {error}"))
}

/// Inits, verifies the enclave, uploads the sealed PCP and starts the job.
async fn start(
    client: &MigrationApiClient,
    init: &InitArgs,
    verifier: &EnclaveVerifier,
    pcp: &[u8],
    credential: &str,
) -> Result<PcpOpener, String> {
    let signer = SoftwareSigner::new(test_key(&init.device_signer_seed), Platform::Android);
    let (opener, enclave_id) = client
        .start_migration(StartMigration {
            integrity_token: &init.integrity_token,
            signer: &signer,
            verifier,
            device_public_key: &init.device_public_key,
            sub: &init.sub,
            proof: &init.proof,
            challenge_id: &init.challenge_id,
            pcp,
            credential,
        })
        .await
        .map_err(|error| error.to_string())?;
    eprintln!("enclave {} verified", enclave_id.as_str());
    Ok(opener)
}

/// Polls until the job ends, returning the download URL of the migrated PCP.
async fn wait(client: &MigrationApiClient, init: &InitArgs) -> Result<String, String> {
    loop {
        let status = client
            .migration_status(&init.device_public_key, &init.sub)
            .await
            .map_err(|error| format!("status failed: {error}"))?;
        match status.status {
            Status::Migrated => {
                return status
                    .download_url
                    .ok_or_else(|| "migrated without a download URL".to_owned());
            }
            Status::Failed => {
                let reason = status.reason.map_or("unknown", |reason| reason.as_str());
                return Err(format!("migration failed: {reason}"));
            }
            Status::Created | Status::Migrating => {}
        }
        if let Some(deadline) = status.deadline
            && unix_now() > deadline + DEADLINE_GRACE.as_secs()
        {
            return Err("the API still reports the job running past its deadline".into());
        }
        tokio::time::sleep(POLL_INTERVAL).await;
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
    use super::read_pcrs;

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
