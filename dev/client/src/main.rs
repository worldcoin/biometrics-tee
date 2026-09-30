//! CLI against the dev host: send a gzipped PCP, get the migrated one back.
//!
//! Dev-only. It verifies no attestation and the host it talks to does none.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod client;
mod error;

use std::{fs, path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use di_dev_api_types::MAX_PCP_BYTES;

use crate::{client::Client, error::Error};

#[derive(Parser)]
#[command(about = "Run a PCP through the dev migration TEE", version)]
struct Cli {
    /// Base URL of the host, e.g. the local end of a `kubectl port-forward`.
    #[arg(long, default_value = "http://localhost:8000", global = true)]
    host: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Migrate a gzipped PCP and write the result.
    Migrate {
        /// The gzipped PCP to send. Not compressed for you — `tar czf` it first.
        input: PathBuf,
        /// Where to write the migrated PCP.
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Report whether the host is up and can reach its enclave.
    Health,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            // The source chain carries the detail; `{error}` alone would hide it.
            let mut source = std::error::Error::source(&error);
            while let Some(cause) = source {
                eprintln!("  caused by: {cause}");
                source = cause.source();
            }
            if let Error::Api {
                allow_retry: true, ..
            }
            | Error::MigrationInProgress = error
            {
                eprintln!("  this one is worth retrying");
            }
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<(), Error> {
    let client = Client::new(&cli.host)?;

    match &cli.command {
        Command::Migrate { input, output } => migrate(&client, input, output),
        Command::Health => {
            let (live, ready) = client.health()?;
            println!("host:    {}", if live { "up" } else { "down" });
            println!(
                "enclave: {}",
                if ready { "reachable" } else { "unreachable" }
            );
            Ok(())
        }
    }
}

fn migrate(client: &Client, input: &PathBuf, output: &PathBuf) -> Result<(), Error> {
    let pcp = fs::read(input).map_err(|source| Error::ReadInput {
        path: input.clone(),
        source,
    })?;

    // Caught here so an oversized file is a local message rather than a round trip and a 413.
    if pcp.len() > MAX_PCP_BYTES {
        return Err(Error::InputTooLarge {
            path: input.clone(),
            bytes: pcp.len(),
            limit: MAX_PCP_BYTES,
        });
    }

    println!("sending {} bytes, this runs to completion...", pcp.len());
    let migrated = client.migrate(pcp)?;

    fs::write(output, &migrated).map_err(|source| Error::WriteOutput {
        path: output.clone(),
        source,
    })?;

    println!("wrote {} bytes to {}", migrated.len(), output.display());
    Ok(())
}
