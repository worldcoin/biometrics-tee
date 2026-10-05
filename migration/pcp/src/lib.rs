//! Map opened legacy PCPs and prepared biometric results into PCP v2.9 content.
//!
//! This is the pure mapping layer, between authenticated extraction and the
//! shared PCP builder. It does not decrypt, authenticate, run inference, generate
//! shares, sign or encrypt.
//! Sensitive types deliberately do not implement `Debug`; never log their JSON.

mod builder;
mod mapping;
mod models;
mod preservation;
mod schema;
mod source;

pub use mapping::{
    MappedPcp, MigrationContext, PreparedBiometrics, generate_migration_signup_id, migrate,
};
pub use models::*;
pub use orb_pcp_defs::v1::Migration;
pub use preservation::verify_preserved_data;
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
    #[error("prepared biometric metadata does not agree with the payloads")]
    MetadataMismatch,
    #[error("source PCP preservation check failed: {0}")]
    PreservationMismatch(&'static str),
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
