//! Host configuration, read once at startup from flags or the environment.

use std::{net::IpAddr, num::NonZeroU16};

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
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Config;

    fn parse(args: &[&str]) -> Result<Config, clap::Error> {
        Config::try_parse_from(std::iter::once("di-migration-host").chain(args.iter().copied()))
    }

    #[test]
    fn defaults_apply_when_only_the_required_values_are_set() {
        let config =
            parse(&["--enclave-cid", "16", "--host-ip", "10.0.0.7"]).expect("should parse");

        assert_eq!(config.enclave_cid, 16);
        assert_eq!(config.enclave_port, 1000);
        assert_eq!(config.port.get(), 8000);
        assert_eq!(config.host_ip.to_string(), "10.0.0.7");
    }

    #[test]
    fn a_missing_enclave_cid_is_rejected() {
        assert!(parse(&["--host-ip", "10.0.0.7"]).is_err());
    }

    #[test]
    fn a_zero_port_is_rejected() {
        assert!(
            parse(&[
                "--enclave-cid",
                "16",
                "--host-ip",
                "10.0.0.7",
                "--port",
                "0"
            ])
            .is_err()
        );
    }

    #[test]
    fn an_invalid_host_ip_is_rejected() {
        assert!(parse(&["--enclave-cid", "16", "--host-ip", "not-an-ip"]).is_err());
    }
}
