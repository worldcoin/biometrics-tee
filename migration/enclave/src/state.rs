//! Boot-scoped state owned by the enclave.

use di_migration_enclave_types::MIGRATION_CHANNEL_DOMAIN;
use pontifex::channel::{ChannelDomain, ChannelEnclave, ChannelError};

/// State fixed for the life of one enclave boot.
pub struct EnclaveState {
    channel: ChannelEnclave,
}

impl EnclaveState {
    /// Generates this boot's channel key; a restart gets a new key and so a new `enclave_id`.
    ///
    /// # Errors
    ///
    /// Fails if the CSPRNG is unavailable.
    pub fn boot() -> Result<Self, ChannelError> {
        Ok(Self {
            channel: ChannelEnclave::generate(ChannelDomain::new(MIGRATION_CHANNEL_DOMAIN))?,
        })
    }

    /// The boot-scoped channel the app seals PCPs to.
    #[must_use]
    pub const fn channel(&self) -> &ChannelEnclave {
        &self.channel
    }
}

#[cfg(test)]
mod tests {
    use super::EnclaveState;

    #[test]
    fn each_boot_gets_a_new_key() {
        let first = EnclaveState::boot().expect("should generate a key");
        let second = EnclaveState::boot().expect("should generate a key");

        assert_ne!(first.channel().public_key(), second.channel().public_key());
    }
}
