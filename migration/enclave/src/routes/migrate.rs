use std::sync::Arc;

use di_migration_enclave_types::{self as enclave_types, MigrateRequest, MigrateResponse};

use crate::state::EnclaveState;

/// Echoes the blob back, standing in for the migration pipeline until it lands.
pub async fn handler(
    _: Arc<EnclaveState>,
    request: MigrateRequest,
) -> Result<MigrateResponse, enclave_types::Error> {
    if request.blob.is_empty() {
        tracing::warn!("migrate request carried no blob");
        return Err(enclave_types::Error::InvalidInput);
    }

    Ok(MigrateResponse {
        blob: request.blob.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use di_migration_enclave_types::{self as enclave_types, MigrateRequest};

    use super::handler;
    use crate::state::EnclaveState;

    fn request(bytes: usize) -> MigrateRequest {
        MigrateRequest {
            blob: vec![7u8; bytes].into(),
        }
    }

    #[tokio::test]
    async fn a_blob_comes_back_unchanged() {
        let response = handler(
            Arc::new(EnclaveState::boot().expect("should generate a key")),
            request(32),
        )
        .await
        .expect("should echo");

        assert_eq!(response.blob, vec![7u8; 32]);
    }

    #[tokio::test]
    async fn an_empty_blob_is_rejected() {
        let error = handler(
            Arc::new(EnclaveState::boot().expect("should generate a key")),
            request(0),
        )
        .await
        .expect_err("should reject");

        assert_eq!(error, enclave_types::Error::InvalidInput);
    }
}
