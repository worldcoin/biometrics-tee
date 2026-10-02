//! Host configuration, read once at startup from flags or the environment.

use std::{
    net::IpAddr,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    time::Duration,
};

use clap::Parser;
use di_migration_enclave_types::PONTIFEX_PORT;

/// Everything the host needs to start; a flag overrides its environment variable.
#[derive(Debug, Clone, Parser)]
#[command(name = "di-migration-host")]
pub struct Config {
    /// The enclave's CID, which `nitro-cli` assigns at boot.
    #[arg(long, env = "ENCLAVE_CID")]
    pub enclave_cid: u32,
    /// vsock port the enclave serves Pontifex on.
    #[arg(long, env = "ENCLAVE_PORT", default_value_t = PONTIFEX_PORT)]
    pub enclave_port: u32,
    /// HTTP port for the internal API.
    #[arg(long, env = "PORT", default_value = "8000")]
    pub port: NonZeroU16,
    /// This pod's IP, which the API stores per job to dispatch it back here.
    #[arg(long, env = "HOST_IP")]
    pub host_ip: IpAddr,
    /// Bucket holding sealed PCPs under `pcp/` and results under `result/`.
    #[arg(long, env = "PCP_BUCKET")]
    pub pcp_bucket: String,
    /// `LocalStack` and other S3-compatible endpoints only serve path-style addressing.
    #[arg(long, env = "S3_FORCE_PATH_STYLE", default_value_t = false, action = clap::ArgAction::Set)]
    pub s3_force_path_style: bool,
    /// Largest sealed PCP the host buffers; larger objects fail the job without being read.
    #[arg(long, env = "MAX_PCP_BYTES", default_value = "33554432")]
    pub max_pcp_bytes: NonZeroUsize,
    /// Table holding the job rows.
    #[arg(long, env = "DYNAMODB_TABLE_NAME")]
    pub dynamodb_table_name: String,
    /// Waiting plus running jobs the host holds; also the capacity the API admits against.
    #[arg(long, env = "QUEUE_CAPACITY", default_value = "16")]
    pub queue_capacity: NonZeroUsize,
    /// A migration running past this fails as `timeout`; keep it below the job deadline.
    #[arg(long, env = "ENCLAVE_MIGRATE_TIMEOUT_SECS", default_value = "300")]
    pub enclave_migrate_timeout_secs: NonZeroU64,
}

impl Config {
    /// The enclave migration deadline.
    #[must_use]
    pub const fn enclave_migrate_timeout(&self) -> Duration {
        Duration::from_secs(self.enclave_migrate_timeout_secs.get())
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Config;

    const REQUIRED: [&str; 8] = [
        "--enclave-cid",
        "16",
        "--host-ip",
        "10.0.0.7",
        "--pcp-bucket",
        "pcp-bucket",
        "--dynamodb-table-name",
        "jobs",
    ];

    fn parse(args: &[&str]) -> Result<Config, clap::Error> {
        Config::try_parse_from(std::iter::once("di-migration-host").chain(args.iter().copied()))
    }

    fn parse_with(extra: &[&str]) -> Result<Config, clap::Error> {
        parse(&[REQUIRED.as_slice(), extra].concat())
    }

    #[test]
    fn defaults_apply_when_only_the_required_values_are_set() {
        let config = parse_with(&[]).expect("should parse");

        assert_eq!(config.enclave_cid, 16);
        assert_eq!(config.enclave_port, 1000);
        assert_eq!(config.port.get(), 8000);
        assert_eq!(config.host_ip.to_string(), "10.0.0.7");
        assert_eq!(config.pcp_bucket, "pcp-bucket");
        assert_eq!(config.dynamodb_table_name, "jobs");
        assert!(!config.s3_force_path_style);
        assert_eq!(config.max_pcp_bytes.get(), 32 * 1024 * 1024);
        assert_eq!(config.queue_capacity.get(), 16);
        assert_eq!(config.enclave_migrate_timeout().as_secs(), 300);
    }

    #[test]
    fn a_missing_enclave_cid_is_rejected() {
        assert!(parse(&REQUIRED[2..]).is_err());
    }

    #[test]
    fn storage_settings_are_required() {
        assert!(parse(&REQUIRED[..4]).is_err());
    }

    #[test]
    fn a_zero_queue_capacity_is_rejected() {
        assert!(parse_with(&["--queue-capacity", "0"]).is_err());
    }

    #[test]
    fn a_zero_port_is_rejected() {
        assert!(parse_with(&["--port", "0"]).is_err());
    }

    #[test]
    fn an_invalid_host_ip_is_rejected() {
        let mut args = REQUIRED;
        args[3] = "not-an-ip";

        assert!(parse(&args).is_err());
    }
}
