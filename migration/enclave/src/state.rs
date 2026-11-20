//! Boot-scoped state owned by the enclave.

use std::sync::Arc;

use di_migration_enclave_primitives::{self as enclave_primitives, MIGRATION_CHANNEL_DOMAIN};
use pontifex::channel::{ChannelDomain, ChannelEnclave};
use tokio::task::JoinHandle;
use world_id_primitives::EdDSAPublicKey;

use crate::{
    attestation::{AttestedKey, Attestor, MAX_CACHED_AGE},
    worker::Worker,
};

/// State fixed for the life of one enclave boot.
pub struct EnclaveState {
    channel: ChannelEnclave,
    /// Attests the channel key's commitment, which apps check before sealing a PCP.
    attested_channel_key: AttestedKey,
    key_wrapper: crate::kms::KeyWrapper,
    manifest_signer: Option<crate::kms::ManifestSigner>,
    /// Signup-service credential signer key used to verify PCP credentials.
    issuer_pubkey: EdDSAPublicKey,
    worker: Box<dyn Worker>,
    report_metadata: crate::debug_report::RuntimeMetadata,
}

impl EnclaveState {
    /// Generates this boot's channel key and attests it; a restart gets a new key and so a new
    /// `enclave_id`. Attesting here rather than per request fails the boot on a broken NSM.
    ///
    /// # Errors
    ///
    /// [`enclave_primitives::Error::ChannelKeyGenerationFailed`] when the channel key cannot be
    /// generated, or [`enclave_primitives::Error::AttestationFailed`] when it cannot be attested.
    pub fn generate(
        attestor: Arc<dyn Attestor>,
        issuer_pubkey: EdDSAPublicKey,
        key_wrapper: crate::kms::KeyWrapper,
        worker: Box<dyn Worker>,
    ) -> Result<Self, enclave_primitives::Error> {
        let channel = ChannelEnclave::generate(ChannelDomain::new(MIGRATION_CHANNEL_DOMAIN))
            .map_err(|error| {
                tracing::error!(?error, "failed to generate the channel key");
                enclave_primitives::Error::ChannelKeyGenerationFailed
            })?;
        let attested_channel_key = AttestedKey::new(
            attestor,
            channel.public_key_commitment().to_vec(),
            MAX_CACHED_AGE,
        )?;

        Ok(Self {
            channel,
            attested_channel_key,
            key_wrapper,
            manifest_signer: None,
            issuer_pubkey,
            worker,
            report_metadata: crate::debug_report::RuntimeMetadata::default(),
        })
    }

    /// The boot-scoped channel the app seals PCPs to.
    #[must_use]
    pub const fn channel(&self) -> &ChannelEnclave {
        &self.channel
    }

    /// Installs observations collected from the initialized enclave runtime before serving.
    pub fn set_report_metadata(&mut self, metadata: crate::debug_report::RuntimeMetadata) {
        self.report_metadata = metadata;
    }

    pub(crate) const fn report_metadata(&self) -> &crate::debug_report::RuntimeMetadata {
        &self.report_metadata
    }

    /// The credential issuer public key this boot verifies signatures against.
    #[must_use]
    pub const fn issuer_pubkey(&self) -> &EdDSAPublicKey {
        &self.issuer_pubkey
    }

    /// KMS wrapper for source-key decryption and per-package recipient generation.
    #[must_use]
    pub const fn key_wrapper(&self) -> &crate::kms::KeyWrapper {
        &self.key_wrapper
    }

    /// Installs the manifest signer selected at boot.
    pub fn set_manifest_signer(&mut self, signer: crate::kms::ManifestSigner) {
        self.manifest_signer = Some(signer);
    }

    /// KMS signer for output PCP manifests.
    #[must_use]
    pub const fn manifest_signer(&self) -> Option<&crate::kms::ManifestSigner> {
        self.manifest_signer.as_ref()
    }

    /// Exits the enclave if the worker died.
    pub fn check_worker(&self) {
        self.worker.check_alive();
    }

    /// Runs the provisioned biometric migration pipeline.
    ///
    /// # Errors
    ///
    /// Returns the worker's validated rejection for invalid or rejected images.
    pub fn migrate(
        &self,
        inputs: di_migration_pcp::PipelineInputs<'_>,
    ) -> Result<crate::worker::MigrationOutput, di_worker_protocol::migration::Failure> {
        self.worker.migrate(inputs)
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
