//! Boot-scoped state owned by the enclave.

/// State fixed for the life of one enclave boot.
#[derive(Debug, Clone)]
pub struct EnclaveState {
    /// Random per boot; mock stand-in for the channel key's commitment.
    pub enclave_id: String,
}

impl EnclaveState {
    /// Draws this boot's identity.
    #[must_use]
    pub fn boot() -> Self {
        Self {
            enclave_id: uuid::Uuid::new_v4().simple().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EnclaveState;

    #[test]
    fn each_boot_gets_a_new_identity() {
        assert_ne!(
            EnclaveState::boot().enclave_id,
            EnclaveState::boot().enclave_id
        );
    }
}
