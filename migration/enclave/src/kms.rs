//! The PCP wire format stores standard Base64 of a KMS ciphertext blob over
//! the raw 32-byte private key, using symmetric encryption without context.

use std::time::{Duration, Instant};

use aws_sdk_kms::{
    Client, config::retry::RetryConfig, error::ProvideErrorMetadata, primitives::Blob,
    types::EncryptionAlgorithmSpec,
};
use base64::{Engine, engine::general_purpose::STANDARD};

/// Includes credential acquisition, connection setup and at most two SDK attempts.
const WRAP_TIMEOUT: Duration = Duration::from_secs(10);

/// Payload-free wrapping failures. SDK errors and request bodies are never logged.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Configuration must identify a KMS key or alias in the client's region.
    #[error("PCP wrapping requires a full KMS key or alias ARN in the configured region")]
    InvalidKeyArn,
    /// The entire operation exceeded its deadline.
    #[error("PCP key wrapping timed out")]
    Timeout,
    /// KMS rejected the caller's permissions.
    #[error("KMS denied PCP key encryption")]
    AccessDenied,
    /// A remote, credential or transport failure; raw errors may contain sensitive data.
    #[error("KMS PCP key encryption failed")]
    RequestFailed,
    /// A successful response did not match the requested key, algorithm or blob bounds.
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
    /// Full key and alias ARNs identify the owning account. KMS resolves an alias
    /// on each request; responses must name a concrete key in that account/region.
    ///
    /// # Errors
    /// Returns [`Error::InvalidKeyArn`] for malformed ARNs or a region mismatch.
    pub fn new(client: &Client, key_arn: String) -> Result<Self, Error> {
        let (scope, _) = arn_parts(&key_arn).ok_or(Error::InvalidKeyArn)?;
        if client
            .config()
            .region()
            .map(aws_sdk_kms::config::Region::as_ref)
            != scope.split(':').nth(3)
        {
            return Err(Error::InvalidKeyArn);
        }
        let config = client
            .config()
            .to_builder()
            .retry_config(RetryConfig::standard().with_max_attempts(2))
            .build();
        Ok(Self {
            client: Client::from_conf(config),
            key_arn,
        })
    }

    /// Encrypts a private key and returns the string stored in `backend_keys.json`.
    /// The SDK receives raw bytes; Base64 is applied only to its ciphertext result.
    ///
    /// # Errors
    /// Fails on timeout, KMS/transport errors or invalid response metadata.
    pub async fn wrap(&self, private_key: &[u8; 32]) -> Result<String, Error> {
        let started = Instant::now();
        let result = self.encrypt(private_key).await;
        tracing::debug!(
            elapsed_ms = started.elapsed().as_millis(),
            success = result.is_ok(),
            "PCP key wrapping finished"
        );
        result
    }

    async fn encrypt(&self, private_key: &[u8; 32]) -> Result<String, Error> {
        let output = tokio::time::timeout(
            WRAP_TIMEOUT,
            self.client
                .encrypt()
                .key_id(&self.key_arn)
                .plaintext(Blob::new(private_key.to_vec()))
                .encryption_algorithm(EncryptionAlgorithmSpec::SymmetricDefault)
                .send(),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|error| {
            if error
                .as_service_error()
                .and_then(ProvideErrorMetadata::code)
                == Some("AccessDeniedException")
            {
                Error::AccessDenied
            } else {
                Error::RequestFailed
            }
        })?;
        if !output
            .key_id
            .as_deref()
            .is_some_and(|actual| response_matches(&self.key_arn, actual))
            || output.encryption_algorithm != Some(EncryptionAlgorithmSpec::SymmetricDefault)
        {
            return Err(Error::InvalidResponse);
        }
        let blob = output.ciphertext_blob.ok_or(Error::InvalidResponse)?;
        if blob.as_ref().is_empty() || blob.as_ref().len() > 6144 {
            return Err(Error::InvalidResponse);
        }
        Ok(STANDARD.encode(blob.as_ref()))
    }
}

// Return the partition/service/region/account scope and resource after validating
// both. Alias resolution is authenticated by the TLS connection to AWS KMS.
fn arn_parts(arn: &str) -> Option<(&str, &str)> {
    let (scope, resource) = arn.rsplit_once(':')?;
    let parts: Vec<_> = scope.split(':').collect();
    if arn.len() > 2048
        || parts.len() != 5
        || parts[0] != "arn"
        || !matches!(parts[1], "aws" | "aws-us-gov" | "aws-cn")
        || parts[2] != "kms"
        || parts[3].is_empty()
        || !parts[3]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || parts[4].len() != 12
        || !parts[4].bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let valid = resource.strip_prefix("key/").is_some_and(|id| {
        !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) || resource.strip_prefix("alias/").is_some_and(|id| {
        !id.is_empty()
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'/'))
    });
    valid.then_some((scope, resource))
}

fn response_matches(requested: &str, actual: &str) -> bool {
    match (arn_parts(requested), arn_parts(actual)) {
        (Some((scope, resource)), Some((actual_scope, actual_resource))) => {
            scope == actual_scope
                && actual_resource.starts_with("key/")
                && (resource.starts_with("alias/") || requested == actual)
        }
        _ => false,
    }
}
