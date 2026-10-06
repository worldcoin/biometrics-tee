//! Boot-scoped state owned by the enclave.

use std::sync::Arc;

use di_migration_enclave_types::{self as enclave_types, MIGRATION_CHANNEL_DOMAIN};
use pontifex::channel::{ChannelDomain, ChannelEnclave};
use tokio::task::JoinHandle;

use crate::{
    attestation::{AttestedKey, Attestor, MAX_CACHED_AGE},
    pipeline::Pipeline,
};

/// State fixed for the life of one enclave boot.
pub struct EnclaveState {
    channel: ChannelEnclave,
    /// Attests the channel key's commitment, which apps check before sealing a PCP.
    attested_channel_key: AttestedKey,
    pipeline: Box<dyn Pipeline>,
}

impl EnclaveState {
    /// Generates this boot's channel key and attests it; a restart gets a new key and so a new
    /// `enclave_id`. Attesting here rather than per request fails the boot on a broken NSM.
    ///
    /// # Errors
    ///
    /// [`enclave_types::Error::Internal`] when the key cannot be generated or attested.
    pub fn generate(
        attestor: Arc<dyn Attestor>,
        pipeline: Box<dyn Pipeline>,
    ) -> Result<Self, enclave_types::Error> {
        let channel = ChannelEnclave::generate(ChannelDomain::new(MIGRATION_CHANNEL_DOMAIN))
            .map_err(|error| {
                tracing::error!(?error, "failed to generate the channel key");
                enclave_types::Error::Internal
            })?;
        let attested_channel_key = AttestedKey::new(
            attestor,
            channel.public_key_commitment().to_vec(),
            MAX_CACHED_AGE,
        )?;

        Ok(Self {
            channel,
            attested_channel_key,
            pipeline,
        })
    }

    /// The boot-scoped channel the app seals PCPs to.
    #[must_use]
    pub const fn channel(&self) -> &ChannelEnclave {
        &self.channel
    }

    /// Migrates opened PCPs.
    #[must_use]
    pub fn pipeline(&self) -> &dyn Pipeline {
        self.pipeline.as_ref()
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
