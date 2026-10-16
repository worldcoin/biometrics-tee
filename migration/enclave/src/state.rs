//! Boot-scoped state owned by the enclave.

use std::{env, str::FromStr, sync::Arc};

use ark_babyjubjub::{EdwardsAffine, Fq};
use di_migration_enclave_primitives::{self as enclave_primitives, MIGRATION_CHANNEL_DOMAIN};
use pontifex::channel::{ChannelDomain, ChannelEnclave};
use tokio::task::JoinHandle;
use world_id_primitives::EdDSAPublicKey;

use crate::{
    attestation::{AttestedKey, Attestor, MAX_CACHED_AGE},
    worker::Worker,
};

/// Decimal `BabyJubJub` affine X coordinate of the credential issuer pubkey.
pub const ISSUER_PUBKEY_X_ENV: &str = "ISSUER_PUBKEY_X";
/// Decimal `BabyJubJub` affine Y coordinate of the credential issuer pubkey.
pub const ISSUER_PUBKEY_Y_ENV: &str = "ISSUER_PUBKEY_Y";
/// Feature flag: when `false`/`0`/`off`, migrate skips credential verification
/// (staging convenience). Defaults to enabled when unset.
pub const CREDENTIAL_VERIFICATION_ENABLED_ENV: &str = "CREDENTIAL_VERIFICATION_ENABLED";

/// State fixed for the life of one enclave boot.
pub struct EnclaveState {
    channel: ChannelEnclave,
    /// Attests the channel key's commitment, which apps check before sealing a PCP.
    attested_channel_key: AttestedKey,
    /// Signup-service credential signer key used to verify PCP credentials.
    issuer_pubkey: EdDSAPublicKey,
    /// Feature flag: when false, migrate skips credential checks (staging only).
    credential_verification_enabled: bool,
    worker: Box<dyn Worker>,
}

impl EnclaveState {
    /// Generates this boot's channel key and attests it; a restart gets a new key and so a new
    /// `enclave_id`. Attesting here rather than per request fails the boot on a broken NSM.
    ///
    /// # Errors
    ///
    /// [`enclave_primitives::Error::Internal`] when the key cannot be generated or attested.
    pub fn generate(
        attestor: Arc<dyn Attestor>,
        issuer_pubkey: EdDSAPublicKey,
        credential_verification_enabled: bool,
        worker: Box<dyn Worker>,
    ) -> Result<Self, enclave_primitives::Error> {
        let channel = ChannelEnclave::generate(ChannelDomain::new(MIGRATION_CHANNEL_DOMAIN))
            .map_err(|error| {
                tracing::error!(?error, "failed to generate the channel key");
                enclave_primitives::Error::Internal
            })?;
        let attested_channel_key = AttestedKey::new(
            attestor,
            channel.public_key_commitment().to_vec(),
            MAX_CACHED_AGE,
        )?;

        Ok(Self {
            channel,
            attested_channel_key,
            issuer_pubkey,
            credential_verification_enabled,
            worker,
        })
    }

    /// Loads [`Self::generate`] with the issuer pubkey from [`ISSUER_PUBKEY_X_ENV`] /
    /// [`ISSUER_PUBKEY_Y_ENV`] and the [`CREDENTIAL_VERIFICATION_ENABLED_ENV`] feature flag.
    ///
    /// # Errors
    ///
    /// When an env var is missing or not a decimal field element, or when key generation /
    /// attestation fails.
    pub fn from_env(attestor: Arc<dyn Attestor>, worker: Box<dyn Worker>) -> anyhow::Result<Self> {
        let issuer_pubkey = issuer_pubkey_from_env()?;
        let credential_verification_enabled = credential_verification_enabled_from_env()?;
        if !credential_verification_enabled {
            tracing::warn!(
                env = CREDENTIAL_VERIFICATION_ENABLED_ENV,
                "credential verification feature flag is disabled"
            );
        }
        Self::generate(
            attestor,
            issuer_pubkey,
            credential_verification_enabled,
            worker,
        )
        .map_err(|error| {
            anyhow::anyhow!("failed to generate and attest the channel key: {error:?}")
        })
    }

    /// The boot-scoped channel the app seals PCPs to.
    #[must_use]
    pub const fn channel(&self) -> &ChannelEnclave {
        &self.channel
    }

    /// The credential issuer public key this boot verifies signatures against.
    #[must_use]
    pub const fn issuer_pubkey(&self) -> &EdDSAPublicKey {
        &self.issuer_pubkey
    }

    /// Feature flag: whether migrate checks the credential's subject, signature, and claims.
    #[must_use]
    pub const fn credential_verification_enabled(&self) -> bool {
        self.credential_verification_enabled
    }

    /// Exits the enclave if the worker died.
    pub fn check_worker(&self) {
        self.worker.check_alive();
    }

    /// The latest document attesting the channel key's commitment.
    pub async fn channel_key_attestation(&self) -> Vec<u8> {
        self.attested_channel_key.document().await
    }

    /// Starts refreshing the channel key's attestation; supervise the handle and exit if it ends.
    ///
    /// # Panics
    ///
    /// Panics if called more than once.
    pub fn start_attestation_refresh(&mut self) -> JoinHandle<()> {
        self.attested_channel_key.start_refresh()
    }
}

/// Reads the issuer `EdDSA` pubkey affine coordinates from the environment.
///
/// # Errors
///
/// When either env var is missing or not a decimal `Fq` element.
fn issuer_pubkey_from_env() -> anyhow::Result<EdDSAPublicKey> {
    let x = env::var(ISSUER_PUBKEY_X_ENV)
        .map_err(|_| anyhow::anyhow!("{ISSUER_PUBKEY_X_ENV} is not set"))?;
    let y = env::var(ISSUER_PUBKEY_Y_ENV)
        .map_err(|_| anyhow::anyhow!("{ISSUER_PUBKEY_Y_ENV} is not set"))?;
    issuer_pubkey_from_decimals(&x, &y)
}

fn issuer_pubkey_from_decimals(x: &str, y: &str) -> anyhow::Result<EdDSAPublicKey> {
    let x = Fq::from_str(x)
        .map_err(|()| anyhow::anyhow!("{ISSUER_PUBKEY_X_ENV} is not a valid decimal Fq element"))?;
    let y = Fq::from_str(y)
        .map_err(|()| anyhow::anyhow!("{ISSUER_PUBKEY_Y_ENV} is not a valid decimal Fq element"))?;
    Ok(EdDSAPublicKey {
        pk: EdwardsAffine { x, y },
    })
}

/// Reads [`CREDENTIAL_VERIFICATION_ENABLED_ENV`]; unset means the feature is on.
///
/// # Errors
///
/// When the value is set but not a recognized boolean.
fn credential_verification_enabled_from_env() -> anyhow::Result<bool> {
    match env::var(CREDENTIAL_VERIFICATION_ENABLED_ENV) {
        Err(env::VarError::NotPresent) => Ok(true),
        Err(error) => Err(anyhow::anyhow!(
            "{CREDENTIAL_VERIFICATION_ENABLED_ENV}: {error}"
        )),
        Ok(value) => match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(anyhow::anyhow!(
                "{CREDENTIAL_VERIFICATION_ENABLED_ENV} must be true or false, got {other:?}"
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::state;

    #[test]
    fn each_boot_gets_a_new_key() {
        let (first, second) = (state(), state());

        assert_ne!(first.channel().public_key(), second.channel().public_key());
    }

    #[tokio::test]
    async fn the_attestation_binds_the_key_commitment() {
        let state = state();

        let document = state.channel_key_attestation().await;

        assert!(document.starts_with(&state.channel().public_key_commitment()));
    }
}
