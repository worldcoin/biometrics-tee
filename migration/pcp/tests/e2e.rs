//! Mapping E2E only: opened old PCP -> mapper -> mock opened new PCP -> final
//! preservation gate. No encryption, signing, archive implementation or inference.
#[path = "support/profiles.rs"]
mod profiles;
mod support;

use di_migration_pcp::*;
use orb_pcp_defs::prost::Message;
use profiles::legacy_profile;
use serde_json::{Value, json};
use support::{context, pipeline, source_files};

// Represent package assembly by its opened output:
// generated capture JSON and migration protobuf, copied raw/legacy files and typed fresh biometrics.
struct MockNewPcp<'a> {
    version: &'static str,
    files: Files,
    legacy: Files,
    fresh: PreparedBiometrics<'a>,
}

fn assemble_mock(mapped: MappedPcp<'_>) -> MockNewPcp<'_> {
    let mut files = mapped.raw_images;
    let info: orb_pcp_defs::v1::Info = mapped.info.into();
    files.insert("info.json".into(), serde_json::to_vec(&info).unwrap());
    files.insert("migration.pb".into(), mapped.migration.encode_to_vec());
    MockNewPcp {
        version: MappedPcp::VERSION,
        files,
        legacy: mapped.legacy,
        fresh: mapped.biometrics,
    }
}

const LEGACY_MEMBERS: &[&str] = &[
    "hashes.json",
    "hashes.sign",
    "iris_codes.json",
    "iris_code_shares_0.json",
    "iris_code_shares_1.json",
    "iris_code_shares_2.json",
    "face_embeddings.json",
    "di_iris_embeddings.pb",
    "di_iris_embeddings_shares_0.pb",
    "di_iris_embeddings_shares_1.pb",
    "di_iris_embeddings_shares_2.pb",
];

fn round_trip(version: &str, optional: bool) {
    let old = legacy_profile(version, optional);
    let source = SourcePcp::parse(old.clone()).unwrap();
    let mapped = migrate(&source, pipeline(), context()).unwrap();
    let new = assemble_mock(mapped);
    // This is the final gate, after the output has been assembled. The reference
    // is still the original source, not a copy extracted from the new package.
    verify_preserved_data(&source, &new.files, &new.legacy).unwrap();
    assert_eq!(new.version, "2.9");

    let info: orb_pcp_defs::v1::Info = serde_json::from_slice(&new.files["info.json"]).unwrap();
    assert_eq!(
        info.signup_id.as_deref(),
        Some("synthetic-orb-signup_di_v1.2.3")
    );
    assert_eq!(info.src_signup_id.as_deref(), Some("synthetic-orb-signup"));
    assert!(info.signup_id_salt.is_none());
    assert_eq!(info.timestamp.as_deref(), Some("1700000000"));
    assert_eq!(info.timestamp_salt.as_deref(), Some("capture-salt"));
    assert_eq!(info.orb_id.as_deref(), Some("original-orb"));
    assert_eq!(info.operator_id.as_deref(), Some("original-operator"));
    assert_eq!(
        info.thumbnail_image_id.as_deref(),
        if version == "0.3" {
            None
        } else {
            Some("face-id")
        }
    );
    assert_eq!(
        info.orb_country.as_deref(),
        if ("2.1"..="2.8").contains(&version) {
            Some("TEST")
        } else {
            None
        }
    );
    assert_eq!(
        info.software_version.as_deref(),
        if ("2.3"..="2.8").contains(&version) {
            Some("old-orb-software")
        } else {
            None
        }
    );
    assert_eq!(
        info.id_commitment.as_deref(),
        if ("2.4"..="2.8").contains(&version) {
            Some("old-commitment")
        } else {
            None
        }
    );
    assert_eq!(
        info.device_public_key.as_deref(),
        if version == "2.8" {
            Some("old-device")
        } else {
            None
        }
    );
    assert_eq!(
        info.left_iris_code_aggregate_image_ids,
        if ("2.6"..="2.8").contains(&version) {
            vec!["left-id", "extra-left"]
        } else {
            vec![]
        }
    );
    assert!(info.right_iris_code_aggregate_image_ids.is_empty());
    assert_eq!(
        info.left_ir_multiframe_image_ids,
        if ("2.6"..="2.8").contains(&version) {
            vec!["extra-left"]
        } else {
            vec![]
        }
    );
    assert!(info.right_ir_multiframe_image_ids.is_empty());
    let migration: Migration = Migration::decode(new.files["migration.pb"].as_slice()).unwrap();
    assert_eq!(migration.src_signup_id, info.src_signup_id);
    assert_eq!(migration.source_pcp_version.as_deref(), Some(version));
    assert_eq!(
        migration.src_signup_id.as_deref(),
        Some("synthetic-orb-signup")
    );
    assert_eq!(migration.tee_version.as_deref(), Some("0.1.0-test"));
    assert_eq!(migration.migrated_ts, Some(1800000000));
    assert_eq!(
        migration.biometric_pipeline_version.as_deref(),
        Some(new.fresh.metadata.biometric_pipeline_version.as_str())
    );
    for name in LEGACY_MEMBERS {
        assert_eq!(new.legacy.get(*name), old.get(*name), "legacy {name}");
    }
    assert_eq!(
        new.legacy.len(),
        LEGACY_MEMBERS
            .iter()
            .filter(|name| old.contains_key(**name))
            .count()
    );
    for (name, bytes) in &old {
        if name.ends_with(".png") {
            assert_eq!(&new.files[name], bytes, "raw capture {name}");
        }
    }
    for excluded in ["info.json", "backend_keys.json", "face_ir_and_thermal.tar"] {
        assert!(!new.legacy.contains_key(excluded));
    }
    assert!(
        !new.legacy
            .keys()
            .any(|path| path.starts_with("normalized_iris/"))
    );
    assert_eq!(new.fresh.face_embeddings.len(), 1);
    assert_eq!(new.fresh.face_embeddings[0].embedding, "new-face");
    assert_eq!(new.fresh.face_embeddings[0].embedding_version, "face-2");
    for eye in [&new.fresh.daugman.left, &new.fresh.daugman.right] {
        assert_eq!(eye.iris_code, Some("new-code"));
        assert_eq!(eye.mask_code, Some("new-mask"));
        assert_eq!(eye.iris_code_shares, ["code-0", "code-1", "code-2"]);
        assert_eq!(eye.mask_code_shares, ["mask-0", "mask-1", "mask-2"]);
    }
    for eye in [
        new.fresh.di.left.as_ref().unwrap(),
        new.fresh.di.right.as_ref().unwrap(),
    ] {
        assert_eq!(eye.embedding, [1, 2]);
        assert_eq!(eye.mirror_embedding, [3, 4]);
        assert_eq!(eye.embedding_f32, [0.1, 0.2]);
        assert_eq!(eye.mirror_embedding_f32, [0.3, 0.4]);
        assert_eq!(eye.embedding_shares, [&[11, 12][..], &[21, 22], &[31, 32]]);
        assert_eq!(
            eye.mirror_embedding_shares,
            [&[13, 14][..], &[23, 24], &[33, 34]]
        );
    }
    for frame in [&new.fresh.left_normalized, &new.fresh.right_normalized] {
        assert_eq!(frame.image, &[1; 16]);
        assert_eq!(frame.mask, &[2; 16]);
        assert_eq!(frame.image_resized, &[3; 8]);
        assert_eq!(frame.mask_resized, &[4; 8]);
    }
}

macro_rules! version_test {
    ($test:ident, $version:literal) => {
        #[test]
        fn $test() {
            round_trip($version, true);
        }
    };
}
version_test!(v0_3_to_new_pcp, "0.3");
version_test!(v2_0_to_new_pcp, "2.0");
version_test!(v2_1_to_new_pcp, "2.1");
version_test!(v2_2_to_new_pcp, "2.2");
version_test!(v2_3_to_new_pcp, "2.3");
version_test!(v2_4_to_new_pcp, "2.4");
version_test!(v2_5_to_new_pcp, "2.5");
version_test!(v2_6_to_new_pcp, "2.6");
version_test!(v2_7_to_new_pcp, "2.7");
version_test!(v2_8_to_new_pcp, "2.8");

#[test]
fn optional_artifacts_can_be_absent() {
    for version in ["2.0", "2.5", "2.6", "2.7", "2.8"] {
        round_trip(version, false);
    }
    for name in LEGACY_MEMBERS
        .iter()
        .filter(|name| !name.starts_with("hashes."))
    {
        let mut old = legacy_profile("2.8", true);
        old.remove(*name);
        let source = SourcePcp::parse(old).unwrap();
        let new = assemble_mock(migrate(&source, pipeline(), context()).unwrap());
        assert!(!new.legacy.contains_key(*name));
        verify_preserved_data(&source, &new.files, &new.legacy).unwrap();
    }
}

#[test]
fn v0_2_without_thumbnail_has_no_new_pcp() {
    let source = SourcePcp::parse(legacy_profile("0.2", true)).unwrap();
    assert_eq!(
        migrate(&source, pipeline(), context()).err(),
        Some(Error::MissingArtifact("face/thumbnail.png"))
    );
}

#[test]
fn every_preserved_member_must_be_present_and_byte_identical_at_completion() {
    let old = legacy_profile("2.8", true);
    let source = SourcePcp::parse(old).unwrap();
    let new = assemble_mock(migrate(&source, pipeline(), context()).unwrap());
    for is_legacy in [false, true] {
        let members = if is_legacy { &new.legacy } else { &new.files };
        for name in members
            .keys()
            .filter(|name| is_legacy || name.ends_with(".png"))
        {
            for missing in [false, true] {
                let mut files = new.files.clone();
                let mut legacy = new.legacy.clone();
                let target = if is_legacy { &mut legacy } else { &mut files };
                if missing {
                    target.remove(name);
                } else {
                    target.get_mut(name).unwrap()[0] ^= 1;
                }
                let reason = match (is_legacy, missing) {
                    (true, true) => "legacy_artifact_missing",
                    (true, false) => "legacy_artifact_changed",
                    (false, true) => "raw_image_missing",
                    (false, false) => "raw_image_changed",
                };
                assert_eq!(
                    verify_preserved_data(&source, &files, &legacy),
                    Err(Error::PreservationMismatch(reason))
                );
            }
        }
    }
    // Even semantically equivalent original JSON must remain byte-identical.
    let mut legacy = new.legacy.clone();
    legacy.get_mut("iris_codes.json").unwrap().push(b' ');
    assert_eq!(
        verify_preserved_data(&source, &new.files, &legacy),
        Err(Error::PreservationMismatch("legacy_artifact_changed"))
    );
}

#[test]
fn completion_rejects_fabricated_history_and_changed_capture_fields() {
    let source = SourcePcp::parse(legacy_profile("2.0", false)).unwrap();
    let new = assemble_mock(migrate(&source, pipeline(), context()).unwrap());
    for name in [
        "iris_code_shares_0.json",
        "info.json",
        "backend_keys.json",
        "face_ir_and_thermal.tar",
    ] {
        let mut legacy = new.legacy.clone();
        legacy.insert(name.into(), vec![1]);
        assert_eq!(
            verify_preserved_data(&source, &new.files, &legacy),
            Err(Error::PreservationMismatch("legacy_artifact_unexpected"))
        );
    }
    let mut files = new.files.clone();
    files.insert("iris/invented.png".into(), vec![1]);
    assert_eq!(
        verify_preserved_data(&source, &files, &new.legacy),
        Err(Error::PreservationMismatch("raw_image_unexpected"))
    );
    for field in [
        "src_signup_id",
        "orb_id",
        "operator_id",
        "timestamp",
        "thumbnail_image_id",
        "orb_country",
        "device_public_key",
    ] {
        let mut files = new.files.clone();
        let mut info: Value = serde_json::from_slice(&files["info.json"]).unwrap();
        info[field] = json!("123456");
        files.insert("info.json".into(), serde_json::to_vec(&info).unwrap());
        assert_eq!(
            verify_preserved_data(&source, &files, &new.legacy),
            Err(Error::PreservationMismatch("capture_metadata_changed"))
        );
    }
}

#[test]
fn completion_requires_the_source_signup_id() {
    let source = SourcePcp::parse(legacy_profile("2.8", true)).unwrap();
    let new = assemble_mock(migrate(&source, pipeline(), context()).unwrap());
    for replacement in [None, Some(Value::Null), Some(json!(""))] {
        let mut files = new.files.clone();
        let mut info: Value = serde_json::from_slice(&files["info.json"]).unwrap();
        match replacement {
            Some(value) => {
                info["src_signup_id"] = value;
            }
            None => {
                info.as_object_mut().unwrap().remove("src_signup_id");
            }
        }
        files.insert("info.json".into(), serde_json::to_vec(&info).unwrap());
        assert_eq!(
            verify_preserved_data(&source, &files, &new.legacy),
            Err(Error::PreservationMismatch("capture_metadata_changed"))
        );
    }
}

#[test]
fn completion_rejects_missing_or_malformed_migration_metadata() {
    let source = SourcePcp::parse(legacy_profile("2.8", true)).unwrap();
    let new = assemble_mock(migrate(&source, pipeline(), context()).unwrap());
    for replacement in [None, Some(Vec::new()), Some(vec![0x12, 0x05, b'x'])] {
        let mut files = new.files.clone();
        let malformed = replacement.as_ref().is_some_and(|bytes| !bytes.is_empty());
        match replacement {
            Some(bytes) => {
                files.insert("migration.pb".into(), bytes);
            }
            None => {
                files.remove("migration.pb");
            }
        }
        let error = verify_preserved_data(&source, &files, &new.legacy).unwrap_err();
        if malformed {
            assert_eq!(error, Error::InvalidProtobuf("migration.pb"));
        } else {
            assert_eq!(error, Error::MissingArtifact("migration.pb"));
        }
    }
}

#[test]
fn completion_checks_migration_source_references_against_original() {
    let source = SourcePcp::parse(legacy_profile("2.8", true)).unwrap();
    let new = assemble_mock(migrate(&source, pipeline(), context()).unwrap());
    for source_id in [true, false] {
        for replacement in [None, Some(""), Some("different")] {
            let mut files = new.files.clone();
            let mut migration = Migration::decode(files["migration.pb"].as_slice()).unwrap();
            if source_id {
                migration.src_signup_id = replacement.map(str::to_owned);
            } else {
                migration.source_pcp_version = replacement.map(str::to_owned);
            }
            files.insert("migration.pb".into(), migration.encode_to_vec());
            assert_eq!(
                verify_preserved_data(&source, &files, &new.legacy),
                Err(Error::PreservationMismatch("migration_source_mismatch"))
            );
        }
    }
}

#[test]
fn completion_bounds_binary_migration_metadata() {
    let source = SourcePcp::parse(legacy_profile("2.8", true)).unwrap();
    let mut ctx = context();
    ctx.migrated_ts = u64::MAX;
    let mut new = assemble_mock(migrate(&source, pipeline(), ctx).unwrap());
    verify_preserved_data(&source, &new.files, &new.legacy).unwrap();
    let migration = Migration::decode(new.files["migration.pb"].as_slice()).unwrap();
    assert_eq!(migration.migrated_ts, Some(u64::MAX));
    new.files
        .insert("migration.pb".into(), vec![0; 1024 * 1024 + 1]);
    assert_eq!(
        verify_preserved_data(&source, &new.files, &new.legacy),
        Err(Error::SizeLimit)
    );
}

#[test]
fn source_signature_is_required_for_mapping_and_completion() {
    for bytes in [None, Some(vec![])] {
        let mut old = legacy_profile("2.8", true);
        let source = SourcePcp::parse(old.clone()).unwrap();
        let new = assemble_mock(migrate(&source, pipeline(), context()).unwrap());
        if let Some(bytes) = bytes {
            old.insert("hashes.sign".into(), bytes);
        } else {
            old.remove("hashes.sign");
        }
        let source = SourcePcp::parse(old).unwrap();
        assert_eq!(
            migrate(&source, pipeline(), context()).err(),
            Some(Error::MissingArtifact("hashes.sign"))
        );
        assert_eq!(
            verify_preserved_data(&source, &new.files, &new.legacy),
            Err(Error::MissingArtifact("hashes.sign"))
        );
    }
}

#[test]
fn intentionally_changed_fields_do_not_fail_preservation() {
    let source = SourcePcp::parse(legacy_profile("2.8", true)).unwrap();
    let mut new = assemble_mock(migrate(&source, pipeline(), context()).unwrap());
    let mut info: Value = serde_json::from_slice(&new.files["info.json"]).unwrap();
    info["orb_id_salt"] = json!("fresh-builder-salt");
    new.files
        .insert("info.json".into(), serde_json::to_vec(&info).unwrap());
    verify_preserved_data(&source, &new.files, &new.legacy).unwrap();
}

#[test]
fn aggregate_ids_pass_through_and_cannot_change_at_completion() {
    for source_value in [
        None,
        Some(Value::Null),
        Some(json!([])),
        Some(json!(["frame-b", "frame-a"])),
    ] {
        let mut files = source_files("2.8");
        let mut info: Value = serde_json::from_slice(&files["info.json"]).unwrap();
        for field in [
            "left_iris_code_aggregate_image_ids",
            "right_iris_code_aggregate_image_ids",
        ] {
            if let Some(value) = &source_value {
                info[field] = value.clone();
            } else {
                info.as_object_mut().unwrap().remove(field);
            }
        }
        files.insert("info.json".into(), serde_json::to_vec(&info).unwrap());
        let source = SourcePcp::parse(files).unwrap();
        let mapped = migrate(&source, pipeline(), context()).unwrap();
        assert_eq!(
            mapped.info.left_iris_code_aggregate_image_ids,
            source.info().left_iris_code_aggregate_image_ids
        );
        assert_eq!(
            mapped.info.right_iris_code_aggregate_image_ids,
            source.info().right_iris_code_aggregate_image_ids
        );
        let new = assemble_mock(mapped);
        verify_preserved_data(&source, &new.files, &new.legacy).unwrap();
        for field in [
            "left_iris_code_aggregate_image_ids",
            "right_iris_code_aggregate_image_ids",
        ] {
            let mut files = new.files.clone();
            let mut info: Value = serde_json::from_slice(&files["info.json"]).unwrap();
            info[field] = json!(["left-id"]);
            files.insert("info.json".into(), serde_json::to_vec(&info).unwrap());
            assert_eq!(
                verify_preserved_data(&source, &files, &new.legacy),
                Err(Error::PreservationMismatch("capture_metadata_changed"))
            );
        }
    }
}

#[test]
fn capture_metadata_changes_are_limited_to_signup_lineage() {
    let mut files = source_files("2.8");
    let mut info: Value = serde_json::from_slice(&files["info.json"]).unwrap();
    // Populate all passthrough scalars, including fields absent in the basic fixture.
    let empty = serde_json::to_value(Info::default()).unwrap();
    for field in empty.as_object().unwrap().keys() {
        if !info.as_object().unwrap().contains_key(field) && !field.ends_with("_image_ids") {
            info[field] = json!(format!("source-{field}"));
        }
    }
    info["left_ir_multiframe_image_ids"] = json!(["frame-b", "frame-a"]);
    info["right_ir_multiframe_image_ids"] = json!([]);
    info["right_iris_code_aggregate_image_ids"] = json!(["frame-c"]);
    files.insert("info.json".into(), serde_json::to_vec(&info).unwrap());
    let source = SourcePcp::parse(files).unwrap();
    let mapped = migrate(&source, pipeline(), context()).unwrap();
    let mut expected = serde_json::to_value(source.info()).unwrap();
    expected["signup_id"] = json!("synthetic-orb-signup_di_v1.2.3");
    expected["src_signup_id"] = json!("synthetic-orb-signup");
    expected["signup_id_salt"] = Value::Null;
    assert_eq!(serde_json::to_value(&mapped.info).unwrap(), expected);
    let new = assemble_mock(mapped);
    verify_preserved_data(&source, &new.files, &new.legacy).unwrap();
    for (field, value) in expected.as_object().unwrap() {
        if field == "signup_id" || field.ends_with("_salt") {
            continue;
        }
        let mut files = new.files.clone();
        let mut info: Value = serde_json::from_slice(&files["info.json"]).unwrap();
        info[field] = if value.is_array() {
            json!(["changed"])
        } else {
            json!("123456")
        };
        files.insert("info.json".into(), serde_json::to_vec(&info).unwrap());
        assert_eq!(
            verify_preserved_data(&source, &files, &new.legacy),
            Err(Error::PreservationMismatch("capture_metadata_changed")),
            "{field}"
        );
    }
}
