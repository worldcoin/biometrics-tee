//! The PCP wire format stores standard Base64 of a KMS ciphertext blob over
//! the raw 32-byte private key, using symmetric encryption without context.

use std::time::Duration;

use aws_sdk_kms::{
    Client,
    config::{BehaviorVersion, Region, retry::RetryConfig, timeout::TimeoutConfig},
    error::{ProvideErrorMetadata, SdkError},
    primitives::Blob,
    types::{EncryptionAlgorithmSpec, MessageType, SigningAlgorithmSpec},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use di_migration_enclave_primitives::kms::{self as parent, CREDENTIALS_PORT, TLS_PORT};
use pontifex::aws_credentials::ParentCredentials;
use zeroize::Zeroizing;

/// Includes credential acquisition, connection setup and at most two SDK attempts.
const KEY_OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(4);
const SIGN_TIMEOUT: Duration = Duration::from_secs(3);

/// Payload-free wrapping failures. SDK errors and request bodies are never logged.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Wrapping requires a full KMS key or alias ARN in the client's region.
    #[error("PCP wrapping key must be a full KMS key or alias ARN in the client region")]
    InvalidConfiguration,
    /// An attempt or the whole operation timed out.
    #[error("PCP key KMS operation timed out")]
    Timeout,
    /// KMS rejected the caller's permissions.
    #[error("KMS denied PCP key operation")]
    AccessDenied,
    /// SDK failure; raw errors may contain sensitive data.
    #[error("KMS PCP key operation failed")]
    RequestFailed,
    /// The response did not contain a nonempty symmetric ciphertext.
    #[error("KMS returned an invalid PCP key response")]
    InvalidResponse,
}

/// Failure to sign a PCP manifest digest without exposing KMS request details.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum SigningError {
    /// The signing key identifier or region is not valid for this KMS client.
    #[error("PCP manifest signing key must be a full KMS key or alias ARN in the client region")]
    InvalidConfiguration,
    /// The KMS signing operation exceeded its deadline.
    #[error("PCP manifest signing timed out")]
    Timeout,
    /// KMS denied permission to use the configured signing key.
    #[error("KMS denied PCP manifest signing")]
    AccessDenied,
    /// KMS or its transport failed without a more specific classification.
    #[error("KMS PCP manifest signing failed")]
    RequestFailed,
    /// KMS returned no usable signature.
    #[error("KMS returned an invalid PCP manifest signature")]
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
    /// A wrapper for the measured key ARN that reaches KMS through the parent.
    ///
    /// TLS terminates in the enclave; the parent relays bytes on [`TLS_PORT`] and serves its
    /// temporary credentials on [`CREDENTIALS_PORT`], which the SDK renews before expiry.
    ///
    /// # Errors
    ///
    /// The ARN's region fixes the endpoint; a caller cannot supply a separate host or region.
    /// Rejects invalid ARNs before constructing a client.
    pub fn from_parent(key_arn: String) -> Result<Self, Error> {
        let region = arn_region(&key_arn).ok_or(Error::InvalidConfiguration)?;
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
                    .operation_timeout(KEY_OPERATION_TIMEOUT)
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

    /// Decrypts a KMS ciphertext blob from a source `backend_keys.json`.
    ///
    /// # Errors
    ///
    /// Fails on timeout, KMS/transport errors, or a response that is not a
    /// 32-byte sealed-box private key.
    pub async fn decrypt(&self, encrypted_private_key: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        if encrypted_private_key.is_empty() {
            return Err(Error::InvalidResponse);
        }
        let output = self
            .client
            .decrypt()
            .key_id(&self.key_arn)
            .ciphertext_blob(Blob::new(encrypted_private_key.to_vec()))
            .encryption_algorithm(EncryptionAlgorithmSpec::SymmetricDefault)
            .send()
            .await
            .map_err(|error| {
                let failure = key_operation_failure(&error);
                tracing::warn!(
                    dependency = "kms", operation = "Decrypt", reason = %failure,
                    "PCP key decryption failed",
                );
                failure
            })?;
        if output.encryption_algorithm != Some(EncryptionAlgorithmSpec::SymmetricDefault) {
            return Err(Error::InvalidResponse);
        }
        let plaintext = output.plaintext.ok_or(Error::InvalidResponse)?;
        if plaintext.as_ref().len() != 32 {
            return Err(Error::InvalidResponse);
        }
        Ok(Zeroizing::new(plaintext.into_inner()))
    }
}

#[async_trait::async_trait]
impl di_migration_pcp::BackendKeyDecryptor for KeyWrapper {
    async fn decrypt_backend_key(
        &self,
        encrypted_private_key: &[u8],
        archive_role: &'static str,
    ) -> Result<Zeroizing<Vec<u8>>, di_migration_pcp::Error> {
        self.decrypt(encrypted_private_key)
            .await
            .map_err(|_| di_migration_pcp::Error::BackendKeyDecryption(archive_role))
    }
}

/// Signs PCP `hashes.json` SHA-256 digests with a separate asymmetric KMS key.
#[derive(Clone)]
pub struct ManifestSigner {
    client: Client,
    key_arn: String,
}

impl ManifestSigner {
    /// Configures the parent-routed KMS client for a measured signing-key ARN.
    ///
    /// The ARN's region fixes the endpoint; a caller cannot supply a separate host or region.
    ///
    /// # Errors
    ///
    /// Returns [`SigningError::InvalidConfiguration`] when `key_arn` is not a complete KMS ARN
    /// for a supported AWS region.
    pub fn from_parent(key_arn: String) -> Result<Self, SigningError> {
        let region = arn_region(&key_arn).ok_or(SigningError::InvalidConfiguration)?;
        parent::hostname(&region).ok_or(SigningError::InvalidConfiguration)?;
        let sdk_config = aws_types::SdkConfig::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(region))
            .build();
        let client = pontifex::kms::client_with_credentials(
            &sdk_config,
            ParentCredentials::new(CREDENTIALS_PORT),
            TLS_PORT,
        );
        validate_key_arn(&client, &key_arn).map_err(|_| SigningError::InvalidConfiguration)?;
        Ok(Self { client, key_arn })
    }

    /// Signs one SHA-256 digest with RSA-PSS, matching the provisioned RSA signing key.
    ///
    /// # Errors
    ///
    /// Returns an error when KMS times out, denies access, fails to sign, or returns no signature.
    pub async fn sign(&self, digest: &[u8; 32]) -> Result<Vec<u8>, SigningError> {
        let output = tokio::time::timeout(
            SIGN_TIMEOUT,
            self.client
                .sign()
                .key_id(&self.key_arn)
                .message(Blob::new(digest.to_vec()))
                .message_type(MessageType::Digest)
                .signing_algorithm(SigningAlgorithmSpec::RsassaPssSha256)
                .send(),
        )
        .await
        .map_err(|_| SigningError::Timeout)?
        .map_err(|error| signing_failure(&error))?;
        let signature = output.signature.ok_or(SigningError::InvalidResponse)?;
        if signature.as_ref().is_empty() {
            return Err(SigningError::InvalidResponse);
        }
        Ok(signature.into_inner())
    }
}

fn arn_region(key_arn: &str) -> Option<String> {
    let components = key_arn.splitn(6, ':').collect::<Vec<_>>();
    let ["arn", partition, "kms", region, account, resource] = components.as_slice() else {
        return None;
    };
    let valid_resource = resource
        .split_once('/')
        .is_some_and(|(kind, id)| matches!(kind, "key" | "alias") && !id.is_empty());
    (!partition.is_empty()
        && parent::hostname(region).is_some()
        && account.len() == 12
        && account.bytes().all(|byte| byte.is_ascii_digit())
        && valid_resource)
        .then(|| (*region).to_owned())
}

fn validate_key_arn(client: &Client, key_arn: &str) -> Result<(), Error> {
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
    Ok(())
}

fn signing_failure(
    error: &aws_sdk_kms::error::SdkError<aws_sdk_kms::operation::sign::SignError>,
) -> SigningError {
    match error {
        SdkError::TimeoutError(_) => SigningError::Timeout,
        SdkError::DispatchFailure(error) if error.is_timeout() => SigningError::Timeout,
        _ if error
            .as_service_error()
            .and_then(ProvideErrorMetadata::code)
            == Some("AccessDeniedException") =>
        {
            SigningError::AccessDenied
        }
        _ => SigningError::RequestFailed,
    }
}

fn key_operation_failure<E>(error: &SdkError<E>) -> Error
where
    E: ProvideErrorMetadata,
{
    match error {
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
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, KeyWrapper, arn_region};

    #[test]
    fn manifest_signing_region_is_taken_from_a_valid_kms_arn() {
        assert_eq!(
            arn_region("arn:aws:kms:us-east-1:000000000000:alias/synthetic"),
            Some("us-east-1".to_owned())
        );
        for arn in [
            "alias/synthetic",
            "arn:aws:kms:evil.example:000000000000:key/synthetic",
            "arn:aws:kms:us-east-1:not-an-account:key/synthetic",
            "arn:aws:kms:us-east-1:000000000000:invalid/synthetic",
        ] {
            assert_eq!(arn_region(arn), None);
        }
    }

    #[test]
    fn the_parent_wrapper_requires_a_valid_full_arn() {
        let wrapper = |arn: &str| KeyWrapper::from_parent(arn.into());

        assert!(wrapper("arn:aws:kms:us-east-1:000000000000:alias/synthetic").is_ok());
        for arn in [
            "alias/synthetic",
            "arn:aws:kms:evil.example:000000000000:key/synthetic",
        ] {
            assert_eq!(wrapper(arn).err(), Some(Error::InvalidConfiguration));
        }
    }
}
