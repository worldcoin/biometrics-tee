//! Final preservation gate. Compare against the original opened source, never
//! against a manifest or copy supplied by the migration output itself.

use orb_pcp_defs::prost::Message;

use crate::source::{legacy_artifact, raw_image};
use crate::{Error, Files, Info, Migration, SourcePcp, parse_json};

/// Assert that source data carried into the completed PCP was preserved.
///
/// Call after assembly, on the actual opened output, before returning/publishing
/// it. `migrated` contains logical files opened from the new PCP's modality
/// archives; `legacy` contains files under its `legacy/` directory. Duplicate
/// archive members must be rejected by the extractor before building either map.
/// A check of mapped content alone cannot detect subsequent assembly corruption.
///
/// Raw captures and all designated legacy members are compared directly as byte
/// slices, including original JSON formatting. Missing, changed and unexpected
/// retained members fail. Capture fields that should remain unchanged are also
/// checked in the active `info.json` after documented timestamp normalization.
/// Source references in `migration.pb` must match the original opened package.
/// New identity and salts are outside
/// this preservation check; their correctness belongs to the mapper/orchestrator.
/// This does not authenticate the source or verify signatures or fresh biometrics.
///
/// Propagate any error as a migration failure; never publish on failure. Errors
/// contain bounded reason codes, not source paths, identifiers or payloads.
pub fn verify_preserved_data(
    source: &SourcePcp,
    migrated: &Files,
    legacy: &Files,
) -> Result<(), Error> {
    verify_artifacts(source, migrated, legacy)?;
    let actual: Info = parse_json(crate::source::required(migrated, "info.json")?, "info.json")?;
    let actual: orb_pcp_defs::v1::Info = actual.into();
    let mut expected: orb_pcp_defs::v1::Info = source.info.clone().into();
    expected.src_signup_id.clone_from(&source.info.signup_id);
    // These fields intentionally change, or receive freshly generated salts.
    expected.signup_id.clone_from(&actual.signup_id);
    expected.signup_id_salt.clone_from(&actual.signup_id_salt);
    expected
        .signup_reason_salt
        .clone_from(&actual.signup_reason_salt);
    expected.orb_id_salt.clone_from(&actual.orb_id_salt);
    expected
        .operator_id_salt
        .clone_from(&actual.operator_id_salt);
    expected.timestamp_salt.clone_from(&actual.timestamp_salt);
    expected.qr_code_salt.clone_from(&actual.qr_code_salt);
    expected
        .software_version_salt
        .clone_from(&actual.software_version_salt);
    expected
        .orb_country_salt
        .clone_from(&actual.orb_country_salt);
    expected
        .id_commitment_salt
        .clone_from(&actual.id_commitment_salt);
    expected
        .device_public_key_salt
        .clone_from(&actual.device_public_key_salt);
    if actual != expected {
        return Err(Error::PreservationMismatch("capture_metadata_changed"));
    }
    let migration_bytes = crate::source::required(migrated, "migration.pb")?;
    if migration_bytes.len() > 1024 * 1024 {
        return Err(Error::SizeLimit);
    }
    let migration =
        Migration::decode(migration_bytes).map_err(|_| Error::InvalidProtobuf("migration.pb"))?;
    let source_signup_id = source
        .info
        .signup_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .ok_or(Error::InvalidField("signup_id"))?;
    if migration.src_signup_id.as_deref() != Some(source_signup_id)
        || migration.source_pcp_version.as_deref() != Some(source.version.as_str())
    {
        return Err(Error::PreservationMismatch("migration_source_mismatch"));
    }
    Ok(())
}

pub(crate) fn verify_artifacts(
    source: &SourcePcp,
    migrated: &Files,
    legacy: &Files,
) -> Result<(), Error> {
    crate::source::required(&source.files, "hashes.json")?;
    crate::source::required(&source.files, "hashes.sign")?;
    for (path, original) in &source.files {
        let (target, missing, changed) = if raw_image(path) {
            (migrated, "raw_image_missing", "raw_image_changed")
        } else if legacy_artifact(path) {
            (legacy, "legacy_artifact_missing", "legacy_artifact_changed")
        } else {
            // Byte preservation applies to raw captures and the legacy inventory.
            // Active capture metadata is checked separately above.
            continue;
        };
        let copy = target
            .get(path)
            .ok_or(Error::PreservationMismatch(missing))?;
        if copy.as_slice() != original.as_slice() {
            return Err(Error::PreservationMismatch(changed));
        }
    }
    if migrated
        .keys()
        .any(|path| raw_image(path) && !source.files.contains_key(path))
    {
        return Err(Error::PreservationMismatch("raw_image_unexpected"));
    }
    if legacy
        .keys()
        .any(|path| !legacy_artifact(path) || !source.files.contains_key(path))
    {
        return Err(Error::PreservationMismatch("legacy_artifact_unexpected"));
    }
    Ok(())
}
