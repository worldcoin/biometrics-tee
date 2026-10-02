use std::sync::Arc;

use di_migration_enclave_types::{self as enclave_types, GetEncryptionKeyRequest, KeyAttestation};

use crate::state::EnclaveState;

/// Returns the full key with an empty document: the mock has no NSM to attest its commitment.
pub async fn handler(
    state: Arc<EnclaveState>,
    _: GetEncryptionKeyRequest,
) -> Result<KeyAttestation, enclave_types::Error> {
    Ok(KeyAttestation {
        document: Vec::new(),
        public_key: state.channel().public_key(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{GetEncryptionKeyRequest, handler};
    use crate::state::EnclaveState;

    #[tokio::test]
    async fn returns_this_boots_full_key() {
        let state = Arc::new(EnclaveState::boot().expect("should generate a key"));

        let response = handler(Arc::clone(&state), GetEncryptionKeyRequest)
            .await
            .expect("should answer");

        assert_eq!(response.public_key.len(), 1216);
        assert_eq!(response.public_key, state.channel().public_key());
    }
}
