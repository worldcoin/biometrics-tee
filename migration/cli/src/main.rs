//! Developer CLI for the migration API.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use migration_api_client::MigrationApiClient;
use reqwest::Url;

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
    InitMigration {
        /// The device public key; sent as a trusted header while device auth is mocked.
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

        /// Uploads this file to the presigned URL to check the whole round trip.
        #[arg(long)]
        upload: Option<std::path::PathBuf>,
    },
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
        Command::InitMigration {
            device_public_key,
            sub,
            proof,
            challenge_id,
            upload,
        } => {
            let response = client
                .init_migration(&device_public_key, &sub, &proof, &challenge_id)
                .await
                .map_err(|error| format!("init-migration failed: {error}"))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&response).map_err(|error| error.to_string())?
            );

            if let Some(path) = upload {
                let pcp = std::fs::read(&path)
                    .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
                client
                    .upload_pcp(&response.upload_url, pcp)
                    .await
                    .map_err(|error| format!("upload failed: {error}"))?;
                println!("uploaded {}", path.display());
            }

            Ok(())
        }
    }
}
