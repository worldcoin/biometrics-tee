//! A migration job: its identity, lifecycle and failure reasons.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

/// A job's ID: a UUID, which also names its S3 objects and job row.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct JobId(String);

/// The value is not a UUID.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("job_id is not a UUID")]
pub struct InvalidJobId;

impl JobId {
    /// A fresh random ID.
    #[must_use]
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// The canonical hyphenated form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for JobId {
    fn default() -> Self {
        Self::new()
    }
}

impl FromStr for JobId {
    type Err = InvalidJobId;

    /// Accepts any UUID spelling and stores the canonical form, so one job has one key.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        uuid::Uuid::parse_str(value)
            .map(|id| Self(id.to_string()))
            .map_err(|_| InvalidJobId)
    }
}

impl TryFrom<String> for JobId {
    type Error = InvalidJobId;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<JobId> for String {
    fn from(id: JobId) -> Self {
        id.0
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A job's lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Init done; the app has not called migrate yet.
    Created,
    /// Dispatched to a host.
    Migrating,
    /// The result is in S3.
    Migrated,
    /// Terminal failure; see [`Reason`].
    Failed,
}

impl Status {
    /// Every status, for parsing.
    pub const ALL: [Self; 4] = [Self::Created, Self::Migrating, Self::Migrated, Self::Failed];

    /// The wire and storage value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Migrating => "migrating",
            Self::Migrated => "migrated",
            Self::Failed => "failed",
        }
    }
}

/// Why a job failed; machine-readable for the app, so values never change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// The host was over its safety cap.
    HostBusy,
    /// The enclave restarted, so the PCP was sealed to a key that no longer exists.
    EnclaveChanged,
    /// The host could not obtain a valid structured migration result from the enclave.
    EnclaveError,
    /// The host could not communicate with the enclave.
    Transport,
    /// The enclave rejected a malformed migration request.
    InvalidInput,
    /// The enclave could not parse or validate the source PCP.
    InvalidPcp,
    /// The enclave could not build the migrated PCP.
    FailedToBuildPcp,
    /// The enclave returned an error introduced by a newer version.
    Unknown,
    /// The enclave's blocking migration task was cancelled.
    MigrationTaskCancelled,
    /// The enclave clock was before the Unix epoch.
    InvalidSystemTime,
    /// The enclave could not generate output PCP recipient keys.
    PcpRecipientKeyGenerationFailed,
    /// PCP manifest signing was not configured in the enclave.
    ManifestSignerUnavailable,
    /// The enclave could not seal the migrated PCP response.
    PcpResponseSealingFailed,
    /// The biometric worker reported an internal failure.
    BiometricPipelineFailed,
    /// The biometric worker omitted required output fields.
    IncompleteBiometricPipelineResult,
    /// The enclave could not generate embedding shares.
    EmbeddingShareGenerationFailed,
    /// The enclave could not decrypt a source PCP backend key.
    PcpKeyDecryptionFailed,
    /// The Nitro Secure Module could not produce an attestation.
    AttestationFailed,
    /// The enclave could not generate its channel key.
    ChannelKeyGenerationFailed,
    /// The credential sub mismatch.
    CredentialSubMismatch,
    /// The credential deserialization failed.
    CredentialDeserializationFailed,
    /// The credential signature verification failed.
    CredentialSignatureVerificationFailed,
    /// The credential signature did not match the credential contents.
    CredentialSignatureInvalid,
    /// The credential claims did not match the PCP `hashes.json`.
    CredentialClaimsMismatch,
    /// The device public key was not valid standard Base64.
    InvalidDevicePublicKeyEncoding,
    /// Reading the PCP or writing the result failed.
    S3Error,
    /// The job did not finish before its deadline.
    Timeout,
}

impl Reason {
    /// Every reason, for parsing.
    pub const ALL: [Self; 27] = [
        Self::HostBusy,
        Self::EnclaveChanged,
        Self::EnclaveError,
        Self::Transport,
        Self::InvalidInput,
        Self::InvalidPcp,
        Self::FailedToBuildPcp,
        Self::Unknown,
        Self::MigrationTaskCancelled,
        Self::InvalidSystemTime,
        Self::PcpRecipientKeyGenerationFailed,
        Self::ManifestSignerUnavailable,
        Self::PcpResponseSealingFailed,
        Self::BiometricPipelineFailed,
        Self::IncompleteBiometricPipelineResult,
        Self::EmbeddingShareGenerationFailed,
        Self::PcpKeyDecryptionFailed,
        Self::AttestationFailed,
        Self::ChannelKeyGenerationFailed,
        Self::CredentialSubMismatch,
        Self::CredentialDeserializationFailed,
        Self::CredentialSignatureVerificationFailed,
        Self::CredentialSignatureInvalid,
        Self::CredentialClaimsMismatch,
        Self::InvalidDevicePublicKeyEncoding,
        Self::S3Error,
        Self::Timeout,
    ];

    /// The wire and storage value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostBusy => "host_busy",
            Self::EnclaveChanged => "enclave_changed",
            Self::EnclaveError => "enclave_error",
            Self::Transport => "transport",
            Self::InvalidInput => "invalid_input",
            Self::InvalidPcp => "invalid_pcp",
            Self::FailedToBuildPcp => "failed_to_build_pcp",
            Self::Unknown => "unknown",
            Self::MigrationTaskCancelled => "migration_task_cancelled",
            Self::InvalidSystemTime => "invalid_system_time",
            Self::PcpRecipientKeyGenerationFailed => "pcp_recipient_key_generation_failed",
            Self::ManifestSignerUnavailable => "manifest_signer_unavailable",
            Self::PcpResponseSealingFailed => "pcp_response_sealing_failed",
            Self::BiometricPipelineFailed => "biometric_pipeline_failed",
            Self::IncompleteBiometricPipelineResult => "incomplete_biometric_pipeline_result",
            Self::EmbeddingShareGenerationFailed => "embedding_share_generation_failed",
            Self::PcpKeyDecryptionFailed => "pcp_key_decryption_failed",
            Self::AttestationFailed => "attestation_failed",
            Self::ChannelKeyGenerationFailed => "channel_key_generation_failed",
            Self::CredentialSubMismatch => "credential_sub_mismatch",
            Self::CredentialDeserializationFailed => "credential_deserialization_failed",
            Self::CredentialSignatureVerificationFailed => {
                "credential_signature_verification_failed"
            }
            Self::CredentialSignatureInvalid => "credential_signature_invalid",
            Self::CredentialClaimsMismatch => "credential_claims_mismatch",
            Self::InvalidDevicePublicKeyEncoding => "invalid_device_public_key_encoding",
            Self::S3Error => "s3_error",
            Self::Timeout => "timeout",
        }
    }
}

/// A value that is not a known [`Status`] or [`Reason`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown value {0:?}")]
pub struct UnknownValue(pub String);

impl FromStr for Status {
    type Err = UnknownValue;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|status| status.as_str() == value)
            .ok_or_else(|| UnknownValue(value.to_owned()))
    }
}

impl FromStr for Reason {
    type Err = UnknownValue;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|reason| reason.as_str() == value)
            .ok_or_else(|| UnknownValue(value.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::{JobId, Reason, Status};

    const ID: &str = "3f0c5e2a-8a51-4c47-9d8e-0b9f3c1d2e4a";

    #[test]
    fn a_uuid_parses_and_round_trips_through_json() {
        let id: JobId = serde_json::from_str(&format!("\"{ID}\"")).expect("should parse");

        assert_eq!(id.as_str(), ID);
        assert_eq!(
            serde_json::to_string(&id).expect("should serialize"),
            format!("\"{ID}\"")
        );
    }

    /// One job, one key: upper case and braces normalize to the canonical form.
    #[test]
    fn other_uuid_spellings_normalize() {
        let id: JobId = format!("{{{}}}", ID.to_uppercase())
            .parse()
            .expect("should parse");

        assert_eq!(id.as_str(), ID);
    }

    #[test]
    fn anything_else_is_rejected() {
        assert!(serde_json::from_str::<JobId>("\"not-a-uuid\"").is_err());
        assert!("../pcp/other".parse::<JobId>().is_err());
    }

    #[test]
    fn new_ids_are_distinct_uuids() {
        let (first, second) = (JobId::new(), JobId::new());

        assert_ne!(first, second);
        assert!(first.as_str().parse::<JobId>().is_ok());
    }

    #[test]
    fn unknown_values_do_not_parse() {
        assert!("pending".parse::<Status>().is_err());
        assert!("oom".parse::<Reason>().is_err());
    }

    /// Pins the values; the app and API branch on them, and the job table stores them.
    #[test]
    fn values_are_stable_on_the_wire() {
        let statuses = [
            (Status::Created, "created"),
            (Status::Migrating, "migrating"),
            (Status::Migrated, "migrated"),
            (Status::Failed, "failed"),
        ];
        for (status, value) in statuses {
            assert_eq!(status.as_str(), value);
            assert_eq!(value.parse::<Status>(), Ok(status));
            assert_eq!(
                serde_json::to_string(&status).expect("json"),
                format!("\"{value}\"")
            );
        }

        let reasons = [
            (Reason::HostBusy, "host_busy"),
            (Reason::EnclaveChanged, "enclave_changed"),
            (Reason::EnclaveError, "enclave_error"),
            (Reason::Transport, "transport"),
            (Reason::InvalidInput, "invalid_input"),
            (Reason::InvalidPcp, "invalid_pcp"),
            (Reason::FailedToBuildPcp, "failed_to_build_pcp"),
            (Reason::Unknown, "unknown"),
            (Reason::MigrationTaskCancelled, "migration_task_cancelled"),
            (Reason::InvalidSystemTime, "invalid_system_time"),
            (
                Reason::PcpRecipientKeyGenerationFailed,
                "pcp_recipient_key_generation_failed",
            ),
            (
                Reason::ManifestSignerUnavailable,
                "manifest_signer_unavailable",
            ),
            (
                Reason::PcpResponseSealingFailed,
                "pcp_response_sealing_failed",
            ),
            (Reason::BiometricPipelineFailed, "biometric_pipeline_failed"),
            (
                Reason::IncompleteBiometricPipelineResult,
                "incomplete_biometric_pipeline_result",
            ),
            (
                Reason::EmbeddingShareGenerationFailed,
                "embedding_share_generation_failed",
            ),
            (Reason::PcpKeyDecryptionFailed, "pcp_key_decryption_failed"),
            (Reason::AttestationFailed, "attestation_failed"),
            (
                Reason::ChannelKeyGenerationFailed,
                "channel_key_generation_failed",
            ),
            (Reason::CredentialSubMismatch, "credential_sub_mismatch"),
            (
                Reason::CredentialDeserializationFailed,
                "credential_deserialization_failed",
            ),
            (
                Reason::CredentialSignatureVerificationFailed,
                "credential_signature_verification_failed",
            ),
            (
                Reason::CredentialSignatureInvalid,
                "credential_signature_invalid",
            ),
            (
                Reason::CredentialClaimsMismatch,
                "credential_claims_mismatch",
            ),
            (
                Reason::InvalidDevicePublicKeyEncoding,
                "invalid_device_public_key_encoding",
            ),
            (Reason::S3Error, "s3_error"),
            (Reason::Timeout, "timeout"),
        ];
        for (reason, value) in reasons {
            assert_eq!(reason.as_str(), value);
            assert_eq!(value.parse::<Reason>(), Ok(reason));
            assert_eq!(
                serde_json::to_string(&reason).expect("json"),
                format!("\"{value}\"")
            );
        }
    }
}
