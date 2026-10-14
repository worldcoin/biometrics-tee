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
use aws_smithy_types::body::SdkBody;
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use zeroize::Zeroize;

/// Includes credential acquisition, connection setup and at most two SDK attempts.
const ENCRYPT_TIMEOUT: Duration = Duration::from_secs(10);
// A 32-byte key encodes to 44 padded Base64 bytes.
const ENCODED_KEY_LEN: usize = 44;

/// Payload-free wrapping failures. SDK errors and request bodies are never logged.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// The KMS request body could not be encoded.
    #[error("failed to encode PCP key encryption request")]
    Encoding,
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
/// transport and credentials.
///
/// Enclave transports must terminate TLS inside the enclave and preserve body
/// ownership without copying plaintext into ordinary transport buffers.
#[derive(Clone)]
pub struct KeyWrapper {
    client: Client,
    key_arn: String,
}

// Fixed-size allocation: encoding never reallocates or creates a temporary
// Base64 string containing the private key. Bytes clones share this owner.
struct SecretBody {
    bytes: Box<[u8]>,
    #[cfg(test)]
    erased: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl SecretBody {
    fn new(key_arn: &str, private_key: &[u8; 32]) -> Result<Self, Error> {
        let key_id = serde_json::to_string(key_arn).map_err(|_| Error::Encoding)?;
        let prefix = format!(
            "{{\"KeyId\":{key_id},\"EncryptionAlgorithm\":\"SYMMETRIC_DEFAULT\",\"Plaintext\":\""
        );
        let mut body = Self {
            bytes: vec![0; prefix.len() + ENCODED_KEY_LEN + 2].into_boxed_slice(),
            #[cfg(test)]
            erased: None,
        };
        body.bytes[..prefix.len()].copy_from_slice(prefix.as_bytes());
        STANDARD
            .encode_slice(
                private_key,
                &mut body.bytes[prefix.len()..prefix.len() + ENCODED_KEY_LEN],
            )
            .map_err(|_| Error::Encoding)?;
        body.bytes[prefix.len() + ENCODED_KEY_LEN..].copy_from_slice(b"\"}");
        Ok(body)
    }
}

impl AsRef<[u8]> for SecretBody {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for SecretBody {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        if let Some(erased) = &self.erased {
            assert!(self.bytes.iter().all(|byte| *byte == 0));
            erased.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
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
    /// The request encodes raw key bytes directly into a zeroizing JSON body.
    /// The returned string is standard Base64 of the KMS ciphertext blob.
    ///
    /// # Errors
    /// Fails on timeout, KMS/transport errors or invalid response metadata.
    pub async fn encrypt(&self, private_key: &[u8; 32]) -> Result<String, Error> {
        self.send(Bytes::from_owner(SecretBody::new(
            &self.key_arn,
            private_key,
        )?))
        .await
    }

    async fn send(&self, body: Bytes) -> Result<String, Error> {
        let output = self
            .client
            .encrypt()
            .key_id(&self.key_arn)
            // The generated serializer sees only an empty, non-secret placeholder.
            // The complete body is installed before signing on every attempt.
            .plaintext(Blob::new(Vec::new()))
            .encryption_algorithm(EncryptionAlgorithmSpec::SymmetricDefault)
            .customize()
            .mutate_request(move |request| {
                request
                    .headers_mut()
                    .insert("content-length", body.len().to_string());
                *request.body_mut() = SdkBody::from(body.clone());
            })
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

#[cfg(test)]
pub(crate) mod tests;
