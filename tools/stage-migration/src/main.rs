//! Runs DI migrations against stage for real stage users, one at a time or as a load test.
//!
//! Every user is provisioned like an app user: a World ID on chain, an Orb enrollment and a
//! staging credential for the reference PCP. Users are deleted again when the run ends.

mod device;
mod load;
mod migration;
mod reference;
mod report;
mod user;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Args, Parser, Subcommand};
use di_migration_client::{MigrationApiClient, sealing::EnclaveVerifier};
use pontifex::PcrConfig;
use reqwest::Url;

use crate::{migration::Stage, user::ReferencePcp, user::StageUser};

const STAGE_API_URL: &str = "https://di-migration-stage.worldcoin.dev";

#[derive(Parser)]
#[command(name = "di-migration-stage", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Provisions one stage user for the PCP, migrates it and deletes the user.
    Migrate {
        #[command(flatten)]
        stage: StageArgs,

        /// Where the migrated PCP is written, readable by the owner only.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Provisions `--users` stage users, then runs `--jobs` migrations with one worker per user,
    /// printing each job as a JSON line and a summary at the end.
    Load(load::LoadArgs),
}

/// Where to migrate, what, and which enclaves to trust.
#[derive(Args)]
struct StageArgs {
    /// Base URL of the migration API.
    #[arg(long, env = "DI_MIGRATION_API_URL", default_value = STAGE_API_URL)]
    api_url: Url,

    /// The decrypted (tier 0) reference PCP directory, repacked for every user.
    #[arg(long)]
    pcp: PathBuf,

    /// PKCS#8 PEM of the staging test Attestation Gateway key, as orb-tools'
    /// `fetch-ag-keys.sh` writes it.
    #[arg(long, env = "AG_PRIVATE_KEY_PATH")]
    ag_private_key: PathBuf,

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

    /// Base back-off after an `at_capacity` rejection; up to as much again is added as jitter.
    #[arg(long, default_value_t = 30)]
    at_capacity_backoff_secs: u64,
}

/// What a run needs: the API, the reference PCP and the key that forges staging devices.
struct Setup {
    stage: Stage,
    reference: ReferencePcp,
    ag_private_key_pem: String,
}

/// Where orb-tools' ownership-proof helper reads the AG key from; it takes no key argument.
const AG_KEY_PATH_ENV: &str = "CI_CANONICAL_REQUEST_SIGNING_PRIVATE_KEY_PATH";

fn main() -> ExitCode {
    let cli = Cli::parse();
    // SAFETY: no other thread exists yet; the runtime is started below.
    unsafe { std::env::set_var(AG_KEY_PATH_ENV, &cli.command.stage().ag_private_key) };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("failed to start the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

impl Command {
    const fn stage(&self) -> &StageArgs {
        match self {
            Self::Migrate { stage, .. } => stage,
            Self::Load(args) => &args.stage,
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Migrate { stage, out } => migrate(stage.setup()?, out.as_deref()).await,
        Command::Load(args) => load::run(args).await,
    }
}

async fn migrate(setup: Setup, out: Option<&Path>) -> Result<()> {
    eprintln!("provisioning a stage user");
    let user = StageUser::provision(&setup.ag_private_key_pem, &setup.reference).await?;
    eprintln!("migrating for {}", user.sub);
    let (report, migrated) = setup.stage.run_job(&user).await;
    println!("{}", report.to_json());

    let written = match (out, migrated) {
        (Some(out), Some(pcp)) => write_private(out, &pcp),
        _ => Ok(()),
    };
    let deleted = user.delete().await.context("delete the stage user");
    report.outcome?;
    written?;
    deleted
}

impl StageArgs {
    fn setup(&self) -> Result<Setup> {
        let verifier = match &self.pcrs {
            Some(path) => EnclaveVerifier::new(vec![read_pcrs(path)?]),
            None if self.insecure_skip_measurements => {
                EnclaveVerifier::dangerously_skip_measurements()
            }
            None => {
                return Err(anyhow!(
                    "--pcrs or --insecure-skip-measurements is required"
                ));
            }
        };
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(300))
            .build()
            .context("build the HTTP client")?;
        let device_public_key =
            crypto_box::SecretKey::generate(&mut rand::rngs::OsRng).public_key();
        Ok(Setup {
            stage: Stage {
                client: MigrationApiClient::with_http_client(&self.api_url, http)?,
                verifier,
                device_public_key: STANDARD.encode(device_public_key.as_bytes()),
                at_capacity_backoff_secs: self.at_capacity_backoff_secs,
            },
            reference: ReferencePcp::read(&self.pcp)?,
            ag_private_key_pem: std::fs::read_to_string(&self.ag_private_key)
                .with_context(|| format!("read {}", self.ag_private_key.display()))?,
        })
    }
}

/// PCR0-2 from the JSON `scripts/build-enclaves.sh` writes, as lower-case hex.
fn read_pcrs(path: &Path) -> Result<PcrConfig> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let pcrs: HashMap<String, String> = serde_json::from_slice(&raw)
        .with_context(|| format!("{} is not PCR JSON", path.display()))?;
    let pcr = |index: u32| -> Result<Vec<u8>> {
        let key = format!("PCR{index}");
        let value = pcrs
            .get(&key)
            .with_context(|| format!("{} has no {key}", path.display()))?;
        hex::decode(value).with_context(|| format!("{key} in {} is not hex", path.display()))
    };

    let image: [u8; 48] = pcr(0)?
        .try_into()
        .map_err(|_| anyhow!("PCR0 in {} is not 48 bytes", path.display()))?;
    Ok(PcrConfig::new(image)
        .with_pcr(1, pcr(1)?)
        .with_pcr(2, pcr(2)?))
}

/// Writes `bytes` to a new file only its owner can read.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _};

    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .with_context(|| format!("write {}", path.display()))
}
