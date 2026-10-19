//! The PCP wire format stores standard Base64 of a KMS ciphertext blob over
//! the raw 32-byte private key, using symmetric encryption without context.

use std::time::Duration;

use aws_sdk_kms::{
    Client,
    config::{BehaviorVersion, Region, retry::RetryConfig, timeout::TimeoutConfig},
    error::{ProvideErrorMetadata, SdkError},
    primitives::Blob,
    types::EncryptionAlgorithmSpec,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use di_migration_enclave_primitives::kms::{self as parent, CREDENTIALS_PORT, TLS_PORT};
use pontifex::aws_credentials::ParentCredentials;
use zeroize::Zeroizing;

/// Includes credential acquisition, connection setup and at most two SDK attempts.
const ENCRYPT_TIMEOUT: Duration = Duration::from_secs(10);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(4);

/// Payload-free wrapping failures. SDK errors and request bodies are never logged.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Wrapping requires a full KMS key or alias ARN in the client's region.
    #[error("PCP wrapping key must be a full KMS key or alias ARN in the client region")]
    InvalidConfiguration,
    /// An attempt or the whole operation timed out.
    #[error("PCP key wrapping timed out")]
    Timeout,
    /// KMS rejected the caller's permissions.
    #[error("KMS denied PCP key encryption")]
    AccessDenied,
    /// SDK failure; raw errors may contain sensitive data.
    #[error("KMS PCP key encryption failed")]
    RequestFailed,
    /// The response did not contain a nonempty symmetric ciphertext.
    #[error("KMS returned an invalid PCP key encryption response")]
    InvalidResponse,
}

/// A shared SDK client and configured wrapping key. The caller supplies the HTTP
/// transport and credentials; enclave transports must terminate TLS in the enclave.
#[derive(Clone)]
pub struct KeyWrapper {
    client: Client,
    key_arn: String,
}

impl KeyWrapper {
    /// A wrapper for the measured key ARN and region that reaches KMS through the parent.
    ///
    /// TLS terminates in the enclave; the parent relays bytes on [`TLS_PORT`] and serves its
    /// temporary credentials on [`CREDENTIALS_PORT`], which the SDK renews before expiry.
    ///
    /// # Errors
    ///
    /// Rejects a region that cannot name a KMS endpoint and ARNs [`Self::new`] rejects.
    pub fn from_parent(key_arn: String, region: String) -> Result<Self, Error> {
        parent::hostname(&region).ok_or(Error::InvalidConfiguration)?;
        let sdk_config = aws_types::SdkConfig::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(region))
            .build();
        let client = pontifex::kms::client_with_credentials(
            &sdk_config,
            ParentCredentials::new(CREDENTIALS_PORT),
            TLS_PORT,
        );

        Self::new(&client, key_arn)
    }

    /// Configures at most two four-second attempts under a ten-second operation deadline.
    /// A full ARN fixes the key's account independently of the credentials provider.
    /// Terraform owns deployment policy; KMS resolves aliases on each request.
    ///
    /// # Errors
    /// Rejects incomplete identifiers and ARNs outside the client's region.
    pub fn new(client: &Client, key_arn: String) -> Result<Self, Error> {
        let parts: Vec<_> = key_arn.splitn(6, ':').collect();
        let ["arn", partition, "kms", region, account, resource] = parts.as_slice() else {
            return Err(Error::InvalidConfiguration);
        };
        let valid_resource = resource
            .split_once('/')
            .is_some_and(|(kind, id)| matches!(kind, "key" | "alias") && !id.is_empty());
        if partition.is_empty()
            || region.is_empty()
            || client.config().region().map(AsRef::as_ref) != Some(*region)
            || account.len() != 12
            || !account.bytes().all(|b| b.is_ascii_digit())
            || !valid_resource
        {
            return Err(Error::InvalidConfiguration);
        }
        let retry = client
            .config()
            .retry_config()
            .cloned()
            .unwrap_or_else(RetryConfig::standard);
        let config = client
            .config()
            .to_builder()
            .retry_config(retry.with_max_attempts(2))
            .timeout_config(
                TimeoutConfig::builder()
                    .operation_timeout(ENCRYPT_TIMEOUT)
                    .operation_attempt_timeout(ATTEMPT_TIMEOUT)
                    .build(),
            )
            .build();
        Ok(Self {
            client: Client::from_conf(config),
            key_arn,
        })
    }

    /// Encrypts a raw private key and returns standard Base64 of the KMS ciphertext
    /// for `backend_keys.json`. `archive_role` is a fixed diagnostic label.
    ///
    /// The raw-key buffer is zeroized when the SDK releases it. SDK-generated JSON
    /// and transport buffers follow normal SDK memory management and are not zeroized.
    ///
    /// # Errors
    /// Fails on timeout, KMS/transport errors or invalid ciphertext responses.
    pub async fn encrypt(
        &self,
        private_key: &[u8; 32],
        archive_role: &'static str,
    ) -> Result<String, Error> {
        let private_key = Zeroizing::new(private_key.to_vec());
        // Preserve the zeroizing owner inside Blob instead of copying the raw key.
        let plaintext = Blob::from_maybe_shared(Bytes::from_owner(private_key));
        let output = self
            .client
            .encrypt()
            .key_id(&self.key_arn)
            .plaintext(plaintext)
            .encryption_algorithm(EncryptionAlgorithmSpec::SymmetricDefault)
            .send()
            .await
            .map_err(|error| {
                let failure = match &error {
                    SdkError::TimeoutError(_) => Error::Timeout,
                    SdkError::DispatchFailure(error) if error.is_timeout() => Error::Timeout,
                    _ if error
                        .as_service_error()
                        .and_then(ProvideErrorMetadata::code)
                        == Some("AccessDeniedException") =>
                    {
                        Error::AccessDenied
                    }
                    _ => Error::RequestFailed,
                };
                tracing::warn!(
                    dependency = "kms", operation = "Encrypt", archive_role, reason = %failure,
                    "PCP key encryption failed",
                );
                failure
            })?;
        if output.encryption_algorithm != Some(EncryptionAlgorithmSpec::SymmetricDefault) {
            return Err(Error::InvalidResponse);
        }
        let blob = output.ciphertext_blob.ok_or(Error::InvalidResponse)?;
        if blob.as_ref().is_empty() {
            return Err(Error::InvalidResponse);
        }
        Ok(STANDARD.encode(blob.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, KeyWrapper};

    #[test]
    fn the_parent_wrapper_requires_a_full_arn_in_the_measured_region() {
        let wrapper = |arn: &str, region: &str| KeyWrapper::from_parent(arn.into(), region.into());

        assert!(
            wrapper(
                "arn:aws:kms:us-east-1:000000000000:alias/synthetic",
                "us-east-1"
            )
            .is_ok()
        );
        for (arn, region) in [
            ("alias/synthetic", "us-east-1"),
            (
                "arn:aws:kms:us-west-2:000000000000:key/synthetic",
                "us-east-1",
            ),
            (
                "arn:aws:kms:evil.example:000000000000:key/synthetic",
                "evil.example",
            ),
        ] {
            assert_eq!(
                wrapper(arn, region).err(),
                Some(Error::InvalidConfiguration)
            );
        }
    }
}
