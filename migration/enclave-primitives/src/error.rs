use serde::{Deserialize, Serialize};

/// Coarse failure classes; they cross to the untrusted host, so they carry no user data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Error {
    /// The request was malformed, e.g. an empty blob or an unknown payload version.
    InvalidInput,
    /// The blob was not sealed to this boot's key, e.g. it targeted an earlier boot.
    RequestNotOpened,
    /// The blocking migration task was cancelled before it returned a result.
    MigrationTaskCancelled,
    /// The enclave could not seal a migration diagnostic to the response key.
    MigrationDiagnosticSealingFailed,
    /// The enclave clock was before the Unix epoch.
    InvalidSystemTime,
    /// The enclave could not generate and wrap the output PCP recipient keys.
    PcpRecipientKeyGenerationFailed,
    /// PCP manifest signing was not configured in the enclave.
    ManifestSignerUnavailable,
    /// The enclave could not seal the migrated PCP response.
    PcpResponseSealingFailed,
    /// The biometric worker reported an internal pipeline failure.
    BiometricPipelineFailed,
    /// The biometric worker rejected an invalid pipeline request.
    BiometricInvalidRequest,
    /// The biometric worker could not decode an input image.
    BiometricInvalidImage,
    /// The biometric worker rejected an image quality check.
    BiometricQualityRejected,
    /// The biometric worker detected a spoof or presentation attack.
    BiometricSpoofDetected,
    /// The biometric worker returned a successful response with required fields missing.
    IncompleteBiometricPipelineResult,
    /// The enclave could not generate Deep Identifier embedding shares.
    EmbeddingShareGenerationFailed,
    /// The enclave could not decrypt a source PCP backend key.
    PcpKeyDecryptionFailed,
    /// The Nitro Secure Module could not produce an attestation.
    AttestationFailed,
    /// The enclave could not generate its channel key.
    ChannelKeyGenerationFailed,
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
    /// An unrecognized worker failure or an error introduced by a newer enclave.
    #[serde(other)]
    Unknown,
}
