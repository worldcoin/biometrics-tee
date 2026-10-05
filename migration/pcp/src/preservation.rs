//! Final check of a completed migration, on its decrypted and opened
//! members. Expected values come from the same inputs as the build request,
//! never from the output itself, and every manifest entry is recomputed from the
//! emitted members.

use std::collections::BTreeMap;

use orb_pcp_defs::{prost::Message, v1::Migration};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::mapping::signup_ids;
use crate::source::{legacy_artifact, raw_image, required};
use crate::{
    Error, Files, Info, MigrationContext, OUTPUT_PCP_VERSION, PreparedBiometrics, SourcePcp,
    parse_json,
};

/// Check a completed migration package before returning or publishing it.
///
/// `files` holds the opened package: top-level members by name and inner-archive
/// members as `<archive stem>/<member>`, the logical paths of `SourcePcp`.
/// `legacy` holds the members under `legacy/` by file name. The extractor must
/// reject duplicate archive members before building either map.
///
/// - Raw captures and `legacy/` members equal the source bytes, including JSON
///   formatting; none is missing or added.
/// - `info.json` is compact with sorted keys, carries the derived signup ID, keeps
///   every other capture field of the source after timestamp normalization, and
///   has a 32-hex-digit salt exactly for each present salted value.
/// - `migration.pb` matches the source and the run's `context` and pipeline version.
/// - `hashes.json` is compact with sorted keys, has `OUTPUT_PCP_VERSION`, and its entries
///   match the SHA-256 of every emitted member and salted value one to one.
///
/// It does not verify `hashes.sign` against the enclave key, recipient
/// encryption or fresh biometric values. Propagate any error as a migration
/// failure; never publish on failure. Errors contain bounded reason codes, not
/// paths, identifiers or payloads.
pub fn verify_completed_pcp(
    source: &SourcePcp,
    biometrics: &PreparedBiometrics<'_>,
    context: &MigrationContext,
    files: &Files,
    legacy: &Files,
) -> Result<(), Error> {
    verify_artifacts(source, files, legacy)?;
    let (source_signup_id, signup_id) = signup_ids(source, biometrics)?;
    let info = verify_info(source, &signup_id, files)?;
    let expected = Migration {
        tee_version: Some(context.tee_version.clone()),
        src_signup_id: Some(source_signup_id.to_owned()),
        source_pcp_version: Some(source.version.as_str().to_owned()),
        migrated_ts: Some(context.migrated_ts),
        biometric_pipeline_version: Some(biometrics.biometric_pipeline_version.clone()),
    };
    verify_migration(source, &expected, files)?;
    verify_manifest(&info, files)
}

fn verify_info(source: &SourcePcp, signup_id: &str, files: &Files) -> Result<Info, Error> {
    let bytes = required(files, "info.json")?;
    canonical::<BTreeMap<String, serde_json::Value>>(
        bytes,
        "info.json",
        "info_json_not_canonical",
    )?;
    let info: Info = parse_json(bytes, "info.json")?;
    if info.signup_id.as_deref() != Some(signup_id) {
        return Err(Error::OutputMismatch("signup_id_mismatch"));
    }
    let actual: orb_pcp_defs::v1::Info = info.clone().into();
    let mut expected: orb_pcp_defs::v1::Info = source.info.clone().into();
    // The signup ID changes and every salt is regenerated; both are checked separately.
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
    for (_, value, salt) in salted_values(&info) {
        match (value, salt) {
            (None, None) => {}
            (Some(_), Some(salt))
                if salt.len() == 32 && salt.bytes().all(|b| b.is_ascii_hexdigit()) => {}
            _ => return Err(Error::OutputMismatch("salt_invalid")),
        }
    }
    Ok(info)
}

fn verify_migration(source: &SourcePcp, expected: &Migration, files: &Files) -> Result<(), Error> {
    let bytes = required(files, "migration.pb")?;
    if bytes.len() > 1024 * 1024 {
        return Err(Error::SizeLimit);
    }
    let migration = Migration::decode(bytes).map_err(|_| Error::InvalidProtobuf("migration.pb"))?;
    if migration.src_signup_id != expected.src_signup_id
        || migration.source_pcp_version.as_deref() != Some(source.version.as_str())
    {
        return Err(Error::PreservationMismatch("migration_source_mismatch"));
    }
    if migration != *expected {
        return Err(Error::OutputMismatch("migration_metadata_mismatch"));
    }
    Ok(())
}

/// Recompute every manifest entry: `value || salt` for each salted value, and
/// each emitted member by its archive member name. `legacy/` members are
/// covered by their original manifest instead.
fn verify_manifest(info: &Info, files: &Files) -> Result<(), Error> {
    let mut manifest: BTreeMap<String, String> = canonical(
        required(files, "hashes.json")?,
        "hashes.json",
        "manifest_not_canonical",
    )?;
    required(files, "hashes.sign")?;
    if manifest.remove("version").as_deref() != Some(OUTPUT_PCP_VERSION) {
        return Err(Error::OutputMismatch("manifest_version"));
    }
    let mut expected = BTreeMap::new();
    for (name, value, salt) in salted_values(info) {
        if let (Some(value), Some(salt)) = (value, salt) {
            expected.insert(
                name.to_owned(),
                sha256_hex(format!("{value}{salt}").as_bytes()),
            );
        }
    }
    for (path, bytes) in files {
        if matches!(path.as_str(), "info.json" | "hashes.json" | "hashes.sign") {
            continue;
        }
        let name = path.rsplit('/').next().unwrap_or(path);
        if expected
            .insert(name.to_owned(), sha256_hex(bytes))
            .is_some()
        {
            return Err(Error::OutputMismatch("manifest_name_duplicate"));
        }
    }
    for (name, hash) in &expected {
        match manifest.get(name) {
            None => return Err(Error::OutputMismatch("manifest_entry_missing")),
            Some(entry) if entry != hash => {
                return Err(Error::OutputMismatch("manifest_hash_mismatch"));
            }
            Some(_) => {}
        }
    }
    if manifest.len() != expected.len() {
        return Err(Error::OutputMismatch("manifest_entry_unexpected"));
    }
    Ok(())
}

/// The salted capture values, in the shared builder's manifest names.
fn salted_values(info: &Info) -> [(&'static str, Option<&str>, Option<&str>); 10] {
    [
        ("signup_id", &info.signup_id, &info.signup_id_salt),
        (
            "signup_reason",
            &info.signup_reason,
            &info.signup_reason_salt,
        ),
        ("orb_id", &info.orb_id, &info.orb_id_salt),
        ("operator_id", &info.operator_id, &info.operator_id_salt),
        ("timestamp", &info.timestamp, &info.timestamp_salt),
        ("qr_code", &info.qr_code, &info.qr_code_salt),
        (
            "id_commitment",
            &info.id_commitment,
            &info.id_commitment_salt,
        ),
        (
            "software_version",
            &info.software_version,
            &info.software_version_salt,
        ),
        ("orb_country", &info.orb_country, &info.orb_country_salt),
        (
            "device_public_key",
            &info.device_public_key,
            &info.device_public_key_salt,
        ),
    ]
    .map(|(name, value, salt)| (name, value.as_deref(), salt.as_deref()))
}

/// Parse JSON that must be byte-identical to its compact, key-sorted encoding.
fn canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    artifact: &'static str,
    reason: &'static str,
) -> Result<T, Error> {
    let value: T = parse_json(bytes, artifact)?;
    if serde_json::to_vec(&value).ok().as_deref() != Some(bytes) {
        return Err(Error::OutputMismatch(reason));
    }
    Ok(value)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn verify_artifacts(source: &SourcePcp, files: &Files, legacy: &Files) -> Result<(), Error> {
    required(&source.files, "hashes.json")?;
    required(&source.files, "hashes.sign")?;
    for (path, original) in &source.files {
        let (target, missing, changed) = if raw_image(path) {
            (files, "raw_image_missing", "raw_image_changed")
        } else if legacy_artifact(path) {
            (legacy, "legacy_artifact_missing", "legacy_artifact_changed")
        } else {
            // Byte preservation applies to raw captures and the legacy inventory.
            // Capture metadata is checked field by field.
            continue;
        };
        let copy = target
            .get(path)
            .ok_or(Error::PreservationMismatch(missing))?;
        if copy.as_slice() != original.as_slice() {
            return Err(Error::PreservationMismatch(changed));
        }
    }
    if files
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
