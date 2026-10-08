use std::sync::Arc;

use di_dev_enclave_primitives::{self as enclave_primitives, MigrateRequest, MigrateResponse};

use crate::state::EnclaveState;

/// Echoes the PCP back, standing in for the sandboxed pipeline until it lands.
pub async fn handler(
    _: Arc<EnclaveState>,
    request: MigrateRequest,
) -> Result<MigrateResponse, enclave_primitives::Error> {
    let bytes = request.pcp.len();

    if bytes == 0 {
        tracing::warn!("migrate request carried no PCP");
        return Err(enclave_primitives::Error::EmptyPcp);
    }

    tracing::info!(bytes, "echoing PCP");
    Ok(MigrateResponse {
        pcp: request.pcp.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use di_dev_enclave_primitives::{self as enclave_primitives, MigrateRequest};

    use super::handler;
    use crate::state::tests::state;

    fn request(bytes: usize) -> MigrateRequest {
        MigrateRequest {
            pcp: vec![7u8; bytes].into(),
        }
    }

    #[tokio::test]
    async fn a_pcp_comes_back_unchanged() {
        let response = handler(state(), request(32)).await.expect("should echo");

        assert_eq!(response.pcp, vec![7u8; 32]);
    }

    #[tokio::test]
    async fn an_empty_pcp_is_rejected() {
        let error = handler(state(), request(0))
            .await
            .expect_err("should reject");

        assert_eq!(error, enclave_primitives::Error::EmptyPcp);
    }
}
