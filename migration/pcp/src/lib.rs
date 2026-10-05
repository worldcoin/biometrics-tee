//! Migrate opened legacy PCPs to the shared builder's migration format.
//!
//! [`SourcePcp::parse`] reads an opened source, [`with_build_request`] turns it and
//! this run's prepared biometrics into the shared builder's request, and
//! [`verify_completed_pcp`] checks the opened result. This crate does not decrypt,
//! authenticate the source, run inference, generate shares, sign or encrypt.
//! Sensitive types deliberately do not implement `Debug`; never log their JSON.

mod builder;
mod mapping;
mod models;
mod preservation;
mod schema;
mod source;

pub use builder::{OUTPUT_VERSION, OutputRecipients, with_build_request};
pub use mapping::{MigrationContext, PreparedBiometrics, generate_migration_signup_id};
pub use models::*;
pub use preservation::verify_completed_pcp;
pub use source::{PipelineInputs, SourcePcp, SourceVersion};

/// Decrypted logical artifact paths and bytes, after opening the nested archives.
/// The extractor must reject duplicate members before constructing this map.
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
    #[error("source lacks capture metadata the PCP builder requires: {0}")]
    MissingCaptureField(&'static str),
    #[error("artifact count or size exceeds the mapping limit")]
    SizeLimit,
    #[error("unsafe logical artifact path")]
    UnsafePath,
    #[error("source archive must be opened before mapping: {0}")]
    UnopenedArtifact(&'static str),
    #[error("unsupported source artifact; an explicit mapping is required")]
    UnsupportedArtifact,
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
