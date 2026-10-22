//! Migrate opened PCPs with the shared PCP builder.
//!
//! [`SourcePcp::parse`] checks and decrypts a source against its manifest.
//! [`build`] prepares the migration request and delegates encryption and archive
//! assembly to the shared builder, using the supplied manifest signer.
//! [`verify_completed_pcp`] checks the opened result. The caller owns source
//! authentication, inference, share generation and recipient keys.
//! Hash consistency does not authenticate the source manifest or unlisted metadata.
//! Sensitive types deliberately do not implement `Debug`; never log their JSON.

mod archive;
mod builder;
mod integrity;
mod mapping;
mod preservation;
mod source;

pub use archive::files_from_tar_gz;
pub use builder::{BuildError, OutputRecipients, build, validate_build_inputs, with_build_request};
pub use mapping::{MigrationContext, PreparedBiometrics};
pub use orb_wld_data_id::{S3Region, SignupId};
pub use preservation::verify_completed_pcp;
pub use source::{BackendKeyDecryptor, PipelineInputs, SourcePcp, SourceVersion};

/// PCP artifact paths and bytes. After parsing, inner archive members use their
/// decrypted logical paths.
pub type Files = std::collections::BTreeMap<String, Vec<u8>>;

/// Bounded, payload-free errors suitable for operational reporting.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("unsupported source PCP version")]
    UnsupportedVersion,
    #[error("missing required artifact: {0}")]
    MissingArtifact(&'static str),
    #[error("invalid JSON or field type in {artifact} at line {line}, column {column}")]
    InvalidJson {
        artifact: &'static str,
        line: usize,
        column: usize,
    },
    #[error("invalid protobuf in {0}")]
    InvalidProtobuf(&'static str),
    #[error("invalid or missing field: {0}")]
    InvalidField(&'static str),
    #[error("source lacks a required capture field: {0}")]
    MissingCaptureField(&'static str),
    #[error("artifact count or size exceeds the mapping limit")]
    SizeLimit,
    #[error("unsafe logical artifact path")]
    UnsafePath,
    #[error("invalid source PCP archive")]
    InvalidArchive,
    #[error("invalid backend key for source archive: {0}")]
    InvalidBackendKey(&'static str),
    #[error("could not decrypt backend key for source archive: {0}")]
    BackendKeyDecryption(&'static str),
    #[error("backend key does not match its public key for source archive: {0}")]
    BackendKeyMismatch(&'static str),
    #[error("could not decrypt source archive: {0}")]
    ArchiveDecryption(&'static str),
    #[error("unsupported source artifact; an explicit mapping is required")]
    UnsupportedArtifact,
    #[error("source PCP integrity check failed: {0}")]
    SourceIntegrity(&'static str),
    #[error("recipient validation failed")]
    RecipientValidation(#[source] alkali::AlkaliError),
    #[error("raw image has no corresponding shared-builder input")]
    UnmappedImage,
    #[error("source PCP preservation check failed: {0}")]
    PreservationMismatch(&'static str),
    #[error("completed PCP check failed: {0}")]
    OutputMismatch(&'static str),
}

fn parse_json<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    artifact: &'static str,
) -> Result<T, Error> {
    if bytes.len() > 1024 * 1024 {
        return Err(Error::SizeLimit);
    }
    // serde errors can include input values. Expose location, never the payload.
    serde_json::from_slice(bytes).map_err(|error| Error::InvalidJson {
        artifact,
        line: error.line(),
        column: error.column(),
    })
}

fn validate_files(files: &Files) -> Result<(), Error> {
    if files.len() > 512
        || files
            .values()
            .try_fold(0usize, |n, v| n.checked_add(v.len()))
            .is_none_or(|n| n > 128 * 1024 * 1024)
    {
        return Err(Error::SizeLimit);
    }
    for path in files.keys() {
        if path.len() > 256
            || path.contains(['\\', '\0'])
            || !path.is_ascii()
            || path
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
        {
            return Err(Error::UnsafePath);
        }
    }
    Ok(())
}
