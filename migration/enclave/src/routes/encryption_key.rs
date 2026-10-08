use std::sync::Arc;

use di_migration_enclave_primitives::{
    self as enclave_primitives, GetEncryptionKeyRequest, KeyAttestation,
};

use crate::state::EnclaveState;

/// Returns the full key and the cached document attesting its commitment; the app checks both
/// before sealing a PCP.
pub async fn handler(
    state: Arc<EnclaveState>,
    _: GetEncryptionKeyRequest,
) -> Result<KeyAttestation, enclave_primitives::Error> {
    Ok(KeyAttestation {
        document: state.channel_key_attestation().await,
        public_key: state.channel().public_key(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{GetEncryptionKeyRequest, handler};

    #[tokio::test]
    async fn returns_this_boots_full_key() {
        let state = Arc::new(crate::test_support::state());

        let response = handler(Arc::clone(&state), GetEncryptionKeyRequest)
            .await
            .expect("should answer");

        assert_eq!(response.public_key.len(), 1216);
        assert_eq!(response.public_key, state.channel().public_key());
        assert_eq!(response.document, state.channel_key_attestation().await);
    }
}
