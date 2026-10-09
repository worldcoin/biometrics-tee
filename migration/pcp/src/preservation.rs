//! Final check of a completed migration, on its decrypted and opened
//! members. Expected values come from the same inputs as the build request,
//! never from the output itself, and every manifest entry is recomputed from the
//! emitted members.

use std::collections::BTreeMap;

use orb_pcp_defs::{prost::Message, v1};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::source::{IRIS_CODE_FILES, normalized_artifact, raw_image, required};
use crate::{Error, Files, MigrationContext, PreparedBiometrics, SourcePcp, parse_json};

/// Check a completed migration package before returning or publishing it.
///
/// `files` holds the opened package: top-level members by name and inner-archive
/// members as `<archive stem>/<member>`, the logical paths of `SourcePcp`. The
/// extractor must reject duplicate archive members before building it.
///
/// - Raw captures, iris codes and shares equal the source bytes, including JSON
///   formatting; none is missing or added.
/// - The normalized iris images and masks are exactly this run's.
/// - `info.json` is compact with sorted keys, carries the context's signup ID,
///   keeps every other field of the source that `pcp.v1.Info` defines, and has a
///   32-hex-digit salt exactly for each present salted value.
/// - `migration.pb` matches the source and the run's `context` and pipeline version.
/// - `hashes.json` is compact with sorted keys, has `orb_pcp::PCP_VERSION`, and
///   its entries match the SHA-256 of every emitted member and salted value one
///   to one.
///
/// It does not verify `hashes.sign` against the enclave key, recipient
/// encryption or fresh face and DI values. Propagate any error as a migration
/// failure; never publish on failure. Errors contain bounded reason codes, not
/// paths, identifiers or payloads.
pub fn verify_completed_pcp(
    source: &SourcePcp,
    biometrics: &PreparedBiometrics<'_>,
    context: &MigrationContext,
    files: &Files,
) -> Result<(), Error> {
    verify_preserved(source, files)?;
    verify_normalized(biometrics, files)?;
    let info = verify_info(source, &context.signup_id.to_string(), files)?;
    let expected = crate::builder::migration(source, biometrics, context);
    verify_migration(&expected, files)?;
    verify_manifest(&info, files)
}

/// Members carried over byte for byte from the source.
fn preserved(path: &str) -> bool {
    raw_image(path) || IRIS_CODE_FILES.contains(&path)
}

fn verify_preserved(source: &SourcePcp, files: &Files) -> Result<(), Error> {
    for (path, original) in source.files.iter().filter(|(path, _)| preserved(path)) {
        let copy = files
            .get(path)
            .ok_or(Error::PreservationMismatch("preserved_artifact_missing"))?;
        if copy != original {
            return Err(Error::PreservationMismatch("preserved_artifact_changed"));
        }
    }
    if files
        .keys()
        .any(|path| preserved(path) && !source.files.contains_key(path))
    {
        return Err(Error::PreservationMismatch("preserved_artifact_unexpected"));
    }
    Ok(())
}

/// The normalized images and masks are this run's, one set per normalized
/// frame; the builder's commitments over them are covered by the manifest.
fn verify_normalized(biometrics: &PreparedBiometrics<'_>, files: &Files) -> Result<(), Error> {
    let mut expected = BTreeMap::new();
    let frames = [
        ("left", &biometrics.left_normalized),
        ("right", &biometrics.right_normalized),
    ]
    .into_iter()
    .chain(
        biometrics
            .extra_normalized
            .iter()
            .map(|(id, frame)| (id.as_str(), frame)),
    );
    for (prefix, frame) in frames {
        for (kind, bytes) in [
            ("image", frame.image),
            ("mask", frame.mask),
            ("image_resized", frame.image_resized),
            ("mask_resized", frame.mask_resized),
        ] {
            expected.insert(
                format!("normalized_iris/{prefix}_normalized_{kind}.bin"),
                bytes,
            );
        }
    }
    let actual: BTreeMap<_, _> = files
        .iter()
        .filter(|(path, _)| {
            normalized_artifact(path)
                && !path.contains("_commitment")
                && !path.contains("_blinding_factors")
        })
        .map(|(path, bytes)| (path.clone(), bytes.as_slice()))
        .collect();
    if actual != expected {
        return Err(Error::OutputMismatch("normalized_iris_mismatch"));
    }
    Ok(())
}

fn verify_info(source: &SourcePcp, signup_id: &str, files: &Files) -> Result<v1::Info, Error> {
    let bytes = required(files, "info.json")?;
    canonical::<BTreeMap<String, serde_json::Value>>(
        bytes,
        "info.json",
        "info_json_not_canonical",
    )?;
    let actual: v1::Info = parse_json(bytes, "info.json")?;
    if actual.signup_id.as_deref() != Some(signup_id) {
        return Err(Error::OutputMismatch("signup_id_mismatch"));
    }
    // The signup ID changes and every salt is regenerated; both are checked separately.
    let mut expected = source.info.clone();
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
    for (_, value, salt) in salted_values(&actual) {
        match (value, salt) {
            (None, None) => {}
            (Some(_), Some(salt))
                if salt.len() == 32 && salt.bytes().all(|b| b.is_ascii_hexdigit()) => {}
            _ => return Err(Error::OutputMismatch("salt_invalid")),
        }
    }
    Ok(actual)
}

fn verify_migration(expected: &v1::Migration, files: &Files) -> Result<(), Error> {
    let bytes = required(files, "migration.pb")?;
    if bytes.len() > 1024 * 1024 {
        return Err(Error::SizeLimit);
    }
    let migration =
        v1::Migration::decode(bytes).map_err(|_| Error::InvalidProtobuf("migration.pb"))?;
    if migration.src_signup_id != expected.src_signup_id
        || migration.source_pcp_version != expected.source_pcp_version
    {
        return Err(Error::PreservationMismatch("migration_source_mismatch"));
    }
    if migration != *expected {
        return Err(Error::OutputMismatch("migration_metadata_mismatch"));
    }
    Ok(())
}

/// Recompute every manifest entry: `value || salt` for each salted value, and
/// each emitted member by its archive member name.
fn verify_manifest(info: &v1::Info, files: &Files) -> Result<(), Error> {
    let mut manifest: BTreeMap<String, String> = canonical(
        required(files, "hashes.json")?,
        "hashes.json",
        "manifest_not_canonical",
    )?;
    required(files, "hashes.sign")?;
    if manifest.remove("version").as_deref() != Some(orb_pcp::PCP_VERSION) {
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
fn salted_values(info: &v1::Info) -> [(&'static str, Option<&str>, Option<&str>); 10] {
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
