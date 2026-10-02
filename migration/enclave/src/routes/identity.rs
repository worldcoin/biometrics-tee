use std::sync::Arc;

use di_migration_enclave_types::{self as enclave_types, Identity, IdentityRequest};

use crate::state::EnclaveState;

/// Mock: no NSM yet, so the attestation and key are empty placeholders.
pub async fn handler(
    state: Arc<EnclaveState>,
    _: IdentityRequest,
) -> Result<Identity, enclave_types::Error> {
    Ok(Identity {
        enclave_id: state.enclave_id.clone(),
        attestation: Vec::new(),
        public_key: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use di_migration_enclave_types::IdentityRequest;

    use super::handler;
    use crate::state::EnclaveState;

    #[tokio::test]
    async fn identity_reports_this_boots_enclave_id() {
        let state = Arc::new(EnclaveState::boot());

        let identity = handler(Arc::clone(&state), IdentityRequest)
            .await
            .expect("should answer");

        assert_eq!(identity.enclave_id, state.enclave_id);
    }
}
