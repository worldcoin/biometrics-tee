//! A forged staging device, as stage's auth proxy and signup backend accept it.

use std::convert::Infallible;

use attested_request::{Platform, sign::Signer};
use integrity_forge::IntegrityForge;

/// An integrity token from the staging test Attestation Gateway key, whose `cnf.jwk` is this
/// device's own signing key.
#[derive(Clone)]
pub struct StageDevice(IntegrityForge);

impl StageDevice {
    pub fn new(ag_private_key_pem: &str) -> anyhow::Result<Self> {
        IntegrityForge::staging_with_ag_private_key_pem(ag_private_key_pem)
            .map(Self)
            .map_err(anyhow::Error::msg)
    }

    pub fn integrity_token(&self) -> &str {
        self.0.integrity_token()
    }
}

impl Signer for StageDevice {
    type Error = Infallible;

    fn platform(&self) -> Platform {
        Platform::Android
    }

    fn sign(&self, client_data_hash: &[u8; 32]) -> Result<Vec<u8>, Infallible> {
        Ok(self.0.sign_digest(client_data_hash))
    }
}
