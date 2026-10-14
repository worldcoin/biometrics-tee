//! The PCP wire format stores standard Base64 of a KMS ciphertext blob over
//! the raw 32-byte private key, using symmetric encryption without context.

use std::{
    error::Error as StdError,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use aws_credential_types::provider::error::CredentialsError;
use aws_sdk_kms::{
    Client,
    config::{retry::RetryConfig, timeout::TimeoutConfig},
    error::{ProvideErrorMetadata, SdkError},
    operation::encrypt::EncryptError,
    primitives::Blob,
    types::EncryptionAlgorithmSpec,
};
use aws_smithy_runtime_api::client::orchestrator::HttpRequest;
use aws_smithy_types::body::SdkBody;
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use zeroize::Zeroize;

/// Includes credential acquisition, connection setup and at most two SDK attempts.
const ENCRYPT_TIMEOUT: Duration = Duration::from_secs(10);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(4);
const ENCODED_KEY_LEN: usize = base64::encoded_len(32, true).expect("32-byte Base64 length fits");
const BODY_SUFFIX: &[u8] = b"\"}";
// KMS Encrypt's maximum CiphertextBlob length, in decoded bytes.
const MAX_CIPHERTEXT_BYTES: usize = 6144;

/// Payload-free wrapping failures. SDK errors and request bodies are never logged.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Wrapping requires a full KMS key or alias ARN in the client's region.
    #[error("PCP wrapping key must be a full KMS key or alias ARN in the client region")]
    InvalidConfiguration,
    /// The SDK request contains fields unsupported by the secret-body encoder.
    #[error("KMS request does not match the PCP key encryption contract")]
    InvalidRequest,
    /// Credential acquisition, an attempt, or the whole operation timed out.
    #[error("PCP key wrapping timed out")]
    Timeout,
    /// KMS rejected the caller's permissions.
    #[error("KMS denied PCP key encryption")]
    AccessDenied,
    /// KMS throttled the operation after retries.
    #[error("KMS throttled PCP key encryption")]
    Throttled,
    /// The configured key is missing, disabled, or unsuitable for encryption.
    #[error("KMS wrapping key is unusable")]
    KeyUnusable,
    /// Credentials could not be acquired or were rejected by KMS.
    #[error("KMS credentials are unavailable or invalid")]
    Credentials,
    /// KMS could not service the operation after retries.
    #[error("KMS service is unavailable")]
    ServiceUnavailable,
    /// The connector failed to exchange a request or response.
    #[error("KMS transport failed")]
    Transport,
    /// An unclassified SDK failure; raw errors may contain sensitive data.
    #[error("KMS PCP key encryption failed")]
    RequestFailed,
    /// The response could not be decoded or its metadata was invalid.
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
    fn new(key_arn: &str, private_key: &[u8; 32]) -> Self {
        let key_id = serde_json::to_string(key_arn).expect("string serialization is infallible");
        let prefix = format!(
            "{{\"KeyId\":{key_id},\"EncryptionAlgorithm\":\"SYMMETRIC_DEFAULT\",\"Plaintext\":\""
        );
        let mut body = Self {
            bytes: vec![0; prefix.len() + ENCODED_KEY_LEN + BODY_SUFFIX.len()].into_boxed_slice(),
            #[cfg(test)]
            erased: None,
        };
        body.bytes[..prefix.len()].copy_from_slice(prefix.as_bytes());
        STANDARD
            .encode_slice(
                private_key,
                &mut body.bytes[prefix.len()..prefix.len() + ENCODED_KEY_LEN],
            )
            .expect("buffer fits the encoded 32-byte key");
        body.bytes[prefix.len() + ENCODED_KEY_LEN..].copy_from_slice(BODY_SUFFIX);
        body
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
    /// Configures at most two four-second attempts under a ten-second operation deadline.
    ///
    /// A full ARN fixes the key's account independently of the credentials provider.
    /// Terraform owns deployment policy; KMS resolves aliases on each request.
    ///
    /// # Errors
    /// Rejects incomplete identifiers and ARNs outside the client's region.
    pub fn new(client: &Client, key_arn: String) -> Result<Self, Error> {
        validate_key_arn(&key_arn, client.config().region().map(AsRef::as_ref))?;
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

    /// Encrypts a private key and returns the string stored in `backend_keys.json`.
    /// Encodes the raw key into a zeroizing JSON body before returning the future,
    /// allowing the caller to release its original key before awaiting KMS.
    /// The returned string is standard Base64 of the KMS ciphertext blob.
    ///
    /// # Errors
    /// Fails on timeout, KMS/transport errors or invalid request/response metadata.
    pub fn encrypt<'a>(
        &'a self,
        private_key: &[u8; 32],
    ) -> impl Future<Output = Result<String, Error>> + Send + use<'a> {
        self.send(Bytes::from_owner(SecretBody::new(
            &self.key_arn,
            private_key,
        )))
    }

    async fn send(&self, body: Bytes) -> Result<String, Error> {
        let expected = serde_json::json!({
            "KeyId": self.key_arn,
            "Plaintext": "",
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
        });
        let attempts = Arc::new(AtomicU32::new(0));
        let counter = attempts.clone();
        let output = self
            .client
            .encrypt()
            .key_id(&self.key_arn)
            // The generated serializer sees only an empty, non-secret placeholder.
            // The complete body is installed before signing on every attempt.
            .plaintext(Blob::new(Vec::new()))
            .encryption_algorithm(EncryptionAlgorithmSpec::SymmetricDefault)
            .customize()
            .map_request(move |request| {
                counter.fetch_add(1, Ordering::Relaxed);
                install_secret_body(request, &expected, &body)
            })
            .send()
            .await
            .map_err(|error| {
                let failure = classify(&error);
                let response = error.raw_response();
                let code = error
                    .as_service_error()
                    .and_then(ProvideErrorMetadata::code);
                let code = code
                    .filter(|code| service_failure(code).is_some())
                    .unwrap_or("Other");
                let request_id = response
                    .and_then(|response| response.headers().get("x-amzn-requestid"))
                    .filter(|id| {
                        id.len() <= 128
                            && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    });
                tracing::warn!(
                    dependency = "kms", operation = "Encrypt", reason = %failure,
                    code, http_status = response.map(|response| response.status().as_u16()),
                    request_id, attempts = attempts.load(Ordering::Relaxed),
                    "PCP key encryption failed",
                );
                failure
            })?;
        let (scope, resource) = self.key_arn.rsplit_once(':').expect("validated KMS ARN");
        let valid_key = output.key_id.as_deref().is_some_and(|key| {
            if resource.starts_with("key/") {
                key == self.key_arn
            } else {
                key.strip_prefix(scope)
                    .and_then(|id| id.strip_prefix(":key/"))
                    .is_some_and(|id| !id.is_empty())
            }
        });
        if !valid_key
            || output.encryption_algorithm != Some(EncryptionAlgorithmSpec::SymmetricDefault)
        {
            return Err(Error::InvalidResponse);
        }
        let blob = output.ciphertext_blob.ok_or(Error::InvalidResponse)?;
        if blob.as_ref().is_empty() || blob.as_ref().len() > MAX_CIPHERTEXT_BYTES {
            return Err(Error::InvalidResponse);
        }
        Ok(STANDARD.encode(blob.as_ref()))
    }
}

fn validate_key_arn(arn: &str, client_region: Option<&str>) -> Result<(), Error> {
    let parts: Vec<_> = arn.splitn(6, ':').collect();
    let ["arn", partition, "kms", region, account, resource] = parts.as_slice() else {
        return Err(Error::InvalidConfiguration);
    };
    let valid_resource = resource.split_once('/').is_some_and(|(kind, id)| {
        matches!(kind, "key" | "alias")
            && !id.is_empty()
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_-".contains(&b))
    });
    if arn.len() > 2048
        || partition.is_empty()
        || !partition
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || region.is_empty()
        || client_region != Some(*region)
        || account.len() != 12
        || !account.bytes().all(|b| b.is_ascii_digit())
        || !valid_resource
    {
        return Err(Error::InvalidConfiguration);
    }
    Ok(())
}

fn install_secret_body(
    mut request: HttpRequest,
    expected: &serde_json::Value,
    body: &Bytes,
) -> Result<HttpRequest, Error> {
    // Only the non-secret SDK placeholder is parsed. Additional fields must not
    // be silently discarded by our fixed, context-free wire representation.
    let placeholder = request.body().bytes().ok_or(Error::InvalidRequest)?;
    let actual: serde_json::Value =
        serde_json::from_slice(placeholder).map_err(|_| Error::InvalidRequest)?;
    if actual != *expected {
        return Err(Error::InvalidRequest);
    }
    request
        .headers_mut()
        .insert("content-length", body.len().to_string());
    *request.body_mut() = SdkBody::from(body.clone());
    Ok(request)
}

fn service_failure(code: &str) -> Option<Error> {
    Some(match code {
        "AccessDeniedException" => Error::AccessDenied,
        "ThrottlingException" | "Throttling" | "LimitExceededException" => Error::Throttled,
        "DisabledException"
        | "NotFoundException"
        | "KMSInvalidStateException"
        | "InvalidKeyUsageException"
        | "InvalidArnException" => Error::KeyUnusable,
        "ExpiredTokenException"
        | "ExpiredToken"
        | "InvalidClientTokenId"
        | "UnrecognizedClientException"
        | "InvalidSignatureException"
        | "SignatureDoesNotMatch" => Error::Credentials,
        "DependencyTimeoutException" => Error::Timeout,
        "KMSInternalException" | "KeyUnavailableException" | "ServiceUnavailableException" => {
            Error::ServiceUnavailable
        }
        _ => return None,
    })
}

fn classify(error: &SdkError<EncryptError>) -> Error {
    let mut source: Option<&(dyn StdError + 'static)> = Some(error);
    while let Some(cause) = source {
        if let Some(error) = cause.downcast_ref::<Error>() {
            return *error;
        }
        if let Some(error) = cause.downcast_ref::<CredentialsError>() {
            return if matches!(error, CredentialsError::ProviderTimedOut(_)) {
                Error::Timeout
            } else {
                Error::Credentials
            };
        }
        source = cause.source();
    }
    if let Some(failure) = error
        .as_service_error()
        .and_then(ProvideErrorMetadata::code)
        .and_then(service_failure)
    {
        return failure;
    }
    if error
        .raw_response()
        .is_some_and(|response| response.status().is_server_error())
    {
        return Error::ServiceUnavailable;
    }
    match error {
        SdkError::TimeoutError(_) => Error::Timeout,
        SdkError::DispatchFailure(error) if error.is_timeout() => Error::Timeout,
        SdkError::DispatchFailure(_) => Error::Transport,
        SdkError::ResponseError(_) => Error::InvalidResponse,
        _ => Error::RequestFailed,
    }
}

#[cfg(test)]
mod tests;
