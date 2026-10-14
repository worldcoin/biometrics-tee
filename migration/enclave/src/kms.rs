//! The PCP wire format stores standard Base64 of a KMS ciphertext blob over
//! the raw 32-byte private key, using symmetric encryption without context.

use std::time::Duration;

use aws_sdk_kms::{
    Client,
    config::{retry::RetryConfig, timeout::TimeoutConfig},
    error::{ProvideErrorMetadata, SdkError},
    primitives::Blob,
    types::EncryptionAlgorithmSpec,
};
use base64::{Engine, engine::general_purpose::STANDARD};

/// Includes credential acquisition, connection setup and at most two SDK attempts.
const ENCRYPT_TIMEOUT: Duration = Duration::from_secs(10);

/// Payload-free wrapping failures. SDK errors and request bodies are never logged.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// The entire operation exceeded its deadline.
    #[error("PCP key wrapping timed out")]
    Timeout,
    /// KMS rejected the caller's permissions.
    #[error("KMS denied PCP key encryption")]
    AccessDenied,
    /// A remote, credential or transport failure; raw errors may contain sensitive data.
    #[error("KMS PCP key encryption failed")]
    RequestFailed,
    /// A successful response did not match the requested algorithm or blob bounds.
    #[error("KMS returned an invalid PCP key encryption response")]
    InvalidResponse,
}

/// A shared SDK client and trusted key identity. The caller supplies the HTTP
/// transport and credentials; enclave callers must terminate TLS in the enclave.
#[derive(Clone)]
pub struct KeyWrapper {
    client: Client,
    key_arn: String,
}

impl KeyWrapper {
    /// Configures two SDK attempts under one wrapping deadline.
    ///
    /// Terraform supplies the key identifier; KMS resolves it on each request.
    #[must_use]
    pub fn new(client: &Client, key_arn: String) -> Self {
        let config = client
            .config()
            .to_builder()
            .retry_config(RetryConfig::standard().with_max_attempts(2))
            .timeout_config(
                TimeoutConfig::builder()
                    .operation_timeout(ENCRYPT_TIMEOUT)
                    .build(),
            )
            .build();
        Self {
            client: Client::from_conf(config),
            key_arn,
        }
    }

    /// Encrypts a private key and returns the string stored in `backend_keys.json`.
    /// The SDK receives raw bytes; Base64 is applied only to its ciphertext result.
    ///
    /// # Errors
    /// Fails on timeout, KMS/transport errors or invalid response metadata.
    pub async fn encrypt(&self, private_key: &[u8; 32]) -> Result<String, Error> {
        let output = self
            .client
            .encrypt()
            .key_id(&self.key_arn)
            .plaintext(Blob::new(private_key.to_vec()))
            .encryption_algorithm(EncryptionAlgorithmSpec::SymmetricDefault)
            .send()
            .await
            .map_err(|error| {
                if matches!(error, SdkError::TimeoutError(_)) {
                    Error::Timeout
                } else if error
                    .as_service_error()
                    .and_then(ProvideErrorMetadata::code)
                    == Some("AccessDeniedException")
                {
                    Error::AccessDenied
                } else {
                    Error::RequestFailed
                }
            })?;
        if output.encryption_algorithm != Some(EncryptionAlgorithmSpec::SymmetricDefault) {
            return Err(Error::InvalidResponse);
        }
        let blob = output.ciphertext_blob.ok_or(Error::InvalidResponse)?;
        if blob.as_ref().is_empty() || blob.as_ref().len() > 6144 {
            return Err(Error::InvalidResponse);
        }
        Ok(STANDARD.encode(blob.as_ref()))
    }
}
