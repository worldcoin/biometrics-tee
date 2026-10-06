//! The migration itself, between opening the app's PCP and sealing the new one back.

use di_migration_enclave_types as enclave_types;

/// What the host passes along with the sealed PCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// Account the ownership proof was verified for; sealed into the new PCP.
    pub sub: String,
    /// The app's attested device key; sealed into the new PCP so only it can refresh.
    pub device_public_key: String,
}

/// Turns an opened PCP into the new one. Runs on a blocking thread.
pub trait Pipeline: Send + Sync {
    /// The new PCP for `pcp`.
    ///
    /// # Errors
    ///
    /// A coarse class only: it reaches the untrusted host.
    fn migrate(&self, pcp: &[u8], job: &Job) -> Result<Vec<u8>, enclave_types::Error>;
}

/// Returns the PCP unchanged until the real pipeline lands, so the channel can be exercised end
/// to end.
#[derive(Debug, Clone, Copy, Default)]
pub struct EchoPipeline;

impl Pipeline for EchoPipeline {
    fn migrate(&self, pcp: &[u8], _: &Job) -> Result<Vec<u8>, enclave_types::Error> {
        Ok(pcp.to_vec())
    }
}
