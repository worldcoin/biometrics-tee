use serde::{Deserialize, Serialize};

/// Coarse failure classes; they cross to the untrusted host, so they carry no user data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Error {
    /// The request was malformed, e.g. an empty blob or an unknown payload version.
    InvalidInput,
    /// The blob was not sealed to this boot's key, e.g. it targeted an earlier boot.
    RequestNotOpened,
    /// The enclave failed while producing a response; detail stays in its log.
    Internal,
    /// The credential sub mismatch.
    CredentialSubMismatch,
    /// Failed to deserialize a World ID credential.
    CredentialDeserializationFailed,
    /// Credential signature verification failed.
    CredentialSignatureVerificationFailed,
    /// Credential signature did not match the credential contents.
    CredentialSignatureInvalid,
    /// Credential claims mismatch.
    CredentialClaimsMismatch,
    /// Failed to parse the PCP.
    InvalidPcp,
    /// Failed to build the PCP.
    FailedToBuildPcp,
    /// The device public key was not valid standard Base64.
    InvalidDevicePublicKeyEncoding,
    /// An error introduced by a newer enclave; the host must still record a failure.
    #[serde(other)]
    Unknown,
}
