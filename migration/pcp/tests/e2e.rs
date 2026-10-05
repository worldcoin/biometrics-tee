//! Migration E2E: opened old PCP -> mapper -> shared builder (signed
//! and encrypted) -> decrypt and open the new PCP -> final check.
//! Inference outputs are fixed synthetic values.
#[path = "support/profiles.rs"]
mod profiles;
mod support;

use di_migration_pcp::*;
use orb_pcp_defs::prost::Message;
use orb_pcp_defs::v1::Migration;
use profiles::legacy_profile;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::{
    OutputKeys, SIGNATURE, build_and_open, check_request, context, pipeline, source_files,
};

fn json_file(files: &Files, name: &str) -> Value {
    serde_json::from_slice(&files[name]).unwrap()
}

fn round_trip(version: &str, optional: bool) {
    let old = legacy_profile(version, optional);
    let source = SourcePcp::parse(old.clone()).unwrap();
    let (bio, ctx) = (pipeline(), context());
    let new = build_and_open(&source, &bio, &ctx);
    // This is the final gate, after the output has been built and reopened. The
    // reference is still the original source, not a copy from the new package.
    verify_completed_pcp(&source, &bio, &ctx, &new.files, &new.legacy).unwrap();

    let manifest = json_file(&new.files, "hashes.json");
    assert_eq!(manifest["version"], OUTPUT_PCP_VERSION);
    assert_eq!(
        new.signed_digest,
        <[u8; 32]>::from(Sha256::digest(&new.files["hashes.json"]))
    );
    assert_eq!(new.files["hashes.sign"], SIGNATURE);

    let info: orb_pcp_defs::v1::Info = serde_json::from_slice(&new.files["info.json"]).unwrap();
    let signup_id = "synthetic-orb-signup_di_v1.2.3";
    assert_eq!(info.signup_id.as_deref(), Some(signup_id));
    // The builder regenerates every salt; the final check verifies their hashes.
    assert_eq!(info.timestamp.as_deref(), Some("1700000000"));
    assert!(info.timestamp_salt.is_some());
    assert_ne!(info.timestamp_salt.as_deref(), Some("capture-salt"));
    assert_eq!(info.signup_reason.as_deref(), Some("synthetic-reason"));
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
        info.orb_public_key_certificate.as_deref(),
        if version == "0.3" {
            None
        } else {
            Some("c3ludGhldGljLWNlcnRpZmljYXRl")
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

    let migration = Migration::decode(new.files["migration.pb"].as_slice()).unwrap();
    assert_eq!(
        migration.src_signup_id.as_deref(),
        Some("synthetic-orb-signup")
    );
    assert_eq!(migration.source_pcp_version.as_deref(), Some(version));
    assert_eq!(migration.tee_version.as_deref(), Some("0.1.0-test"));
    assert_eq!(migration.migrated_ts, Some(1800000000));
    assert_eq!(
        migration.biometric_pipeline_version.as_deref(),
        Some("pipeline-1")
    );

    assert_ne!(new.files["hashes.json"], old["hashes.json"]);
    assert!(
        !new.files
            .contains_key("normalized_iris/extra-left_normalized_image.bin"),
        "old extra-frame normalization must not be relabeled as fresh output"
    );

    // Fresh outputs, encoded by the shared builder.
    let face = json_file(&new.files, "face_embeddings.json");
    assert_eq!(
        face,
        json!([{
            "embedding": "new-face",
            "embedding_type": "test-face",
            "embedding_version": "face-2",
            "embedding_inference_backend": "test-runtime",
        }])
    );
    let iris = json_file(&new.files, "iris_codes.json");
    assert_eq!(iris["IRIS_version"], "iris-1");
    for side in ["left", "right"] {
        assert_eq!(iris[format!("{side}_iris_code")], "new-code");
        assert_eq!(iris[format!("{side}_mask_code")], "new-mask");
    }
    for i in 0..3 {
        let share = json_file(&new.files, &format!("iris_code_shares_{i}.json"));
        assert_eq!(share["IRIS_shares_version"], "test-iris-shares");
        for side in ["left", "right"] {
            assert_eq!(
                share[format!("{side}_iris_code_shares")],
                format!("code-{i}")
            );
            assert_eq!(
                share[format!("{side}_mask_code_shares")],
                format!("mask-{i}")
            );
        }
        let di = orb_pcp_defs::v1::DiIrisEmbeddingShares::decode(
            new.files[&format!("di_iris_embeddings_shares_{i}.pb")].as_slice(),
        )
        .unwrap()
        .share_v1
        .unwrap();
        let first = 10 * (i as u32 + 1);
        assert_eq!(di.left_share, [first + 1, first + 2]);
        assert_eq!(di.right_mirror_share, [first + 3, first + 4]);
    }
    let di =
        orb_pcp_defs::v1::DiIrisEmbeddings::decode(new.files["di_iris_embeddings.pb"].as_slice())
            .unwrap()
            .embedding_v1
            .unwrap();
    assert_eq!(di.model_version, "1.2.3");
    assert_eq!(di.embedding_inference_backend, "test-runtime");
    assert_eq!(di.left_embedding, [1, 2]);
    assert_eq!(di.right_mirror_embedding, [3, 4]);
    assert_eq!(di.left_embedding_f32, [0.1, 0.2]);
    for side in ["left", "right"] {
        for (kind, bytes) in [
            ("image", &[1u8; 16][..]),
            ("mask", &[2; 16]),
            ("image_resized", &[3; 8]),
            ("mask_resized", &[4; 8]),
        ] {
            let name = format!("normalized_iris/{side}_normalized_{kind}.bin");
            assert_eq!(new.files[&name], bytes, "{name}");
        }
        // Generated by the builder; Hyrax leaves them empty for inputs of at
        // most 256 bytes, such as these synthetic frames.
        for derived in ["commitment", "blinding_factors"] {
            let name = format!("normalized_iris/{side}_normalized_image_{derived}.bin");
            assert!(new.files.contains_key(&name), "{name}");
        }
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
    // Every optional legacy file of a complete source may be missing.
    let (bio, ctx) = (pipeline(), context());
    let complete = SourcePcp::parse(legacy_profile("2.8", true)).unwrap();
    let legacy = build_and_open(&complete, &bio, &ctx).legacy;
    for name in legacy.keys().filter(|name| !name.starts_with("hashes.")) {
        let mut old = legacy_profile("2.8", true);
        old.remove(name);
        let source = SourcePcp::parse(old).unwrap();
        let new = build_and_open(&source, &bio, &ctx);
        verify_completed_pcp(&source, &bio, &ctx, &new.files, &new.legacy).unwrap();
    }
}

#[test]
fn opened_thermal_and_fraud_images_use_their_modality_archives() {
    let mut old = legacy_profile("2.8", true);
    for name in ["scc_rgb", "left_rgb", "right_rgb", "left_depth"] {
        old.insert(
            format!("fraud/{name}.png"),
            format!("synthetic-{name}").into_bytes(),
        );
    }
    let source = SourcePcp::parse(old.clone()).unwrap();
    let (bio, ctx) = (pipeline(), context());
    let new = build_and_open(&source, &bio, &ctx);
    verify_completed_pcp(&source, &bio, &ctx, &new.files, &new.legacy).unwrap();
    for name in [
        "face_ir_and_thermal/face_ir.png",
        "face_ir_and_thermal/thermal.png",
        "fraud/scc_rgb.png",
        "fraud/left_depth.png",
    ] {
        assert_eq!(new.files[name], old[name], "{name}");
    }
    assert!(!new.files.contains_key("fraud/right_depth.png"));

    // The builder needs all three RGB images for a fraud archive.
    old.remove("fraud/scc_rgb.png");
    let source = SourcePcp::parse(old).unwrap();
    assert_eq!(
        check_request(&source, &pipeline(), &context()).err(),
        Some(Error::InvalidField("raw_image"))
    );
}

#[test]
fn v0_2_without_thumbnail_has_no_new_pcp() {
    let source = SourcePcp::parse(legacy_profile("0.2", true)).unwrap();
    assert_eq!(
        check_request(&source, &pipeline(), &context()).err(),
        Some(Error::MissingArtifact("face/thumbnail.png"))
    );
}

#[test]
fn every_preserved_member_must_be_present_and_byte_identical_at_completion() {
    let old = legacy_profile("2.8", true);
    let source = SourcePcp::parse(old).unwrap();
    let (bio, ctx) = (pipeline(), context());
    let new = build_and_open(&source, &bio, &ctx);
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
                    verify_completed_pcp(&source, &bio, &ctx, &files, &legacy),
                    Err(Error::PreservationMismatch(reason))
                );
            }
        }
    }
    // Even semantically equivalent original JSON must remain byte-identical.
    let mut legacy = new.legacy.clone();
    legacy.get_mut("iris_codes.json").unwrap().push(b' ');
    assert_eq!(
        verify_completed_pcp(&source, &bio, &ctx, &new.files, &legacy),
        Err(Error::PreservationMismatch("legacy_artifact_changed"))
    );
}

#[test]
fn completion_rejects_fabricated_history_and_changed_capture_fields() {
    let source = SourcePcp::parse(legacy_profile("2.0", false)).unwrap();
    let (bio, ctx) = (pipeline(), context());
    let new = build_and_open(&source, &bio, &ctx);
    for name in [
        "iris_code_shares_0.json",
        "info.json",
        "backend_keys.json",
        "face_ir_and_thermal.tar",
    ] {
        let mut legacy = new.legacy.clone();
        legacy.insert(name.into(), vec![1]);
        assert_eq!(
            verify_completed_pcp(&source, &bio, &ctx, &new.files, &legacy),
            Err(Error::PreservationMismatch("legacy_artifact_unexpected"))
        );
    }
    let mut files = new.files.clone();
    files.insert("iris/invented.png".into(), vec![1]);
    assert_eq!(
        verify_completed_pcp(&source, &bio, &ctx, &files, &new.legacy),
        Err(Error::PreservationMismatch("raw_image_unexpected"))
    );
    for field in [
        "orb_id",
        "operator_id",
        "timestamp",
        "thumbnail_image_id",
        "orb_country",
        "device_public_key",
    ] {
        let mut files = new.files.clone();
        let mut info = json_file(&files, "info.json");
        info[field] = json!("123456");
        files.insert("info.json".into(), serde_json::to_vec(&info).unwrap());
        assert_eq!(
            verify_completed_pcp(&source, &bio, &ctx, &files, &new.legacy),
            Err(Error::PreservationMismatch("capture_metadata_changed"))
        );
    }
}

#[test]
fn completion_rejects_missing_or_malformed_migration_metadata() {
    let source = SourcePcp::parse(legacy_profile("2.8", true)).unwrap();
    let (bio, ctx) = (pipeline(), context());
    let new = build_and_open(&source, &bio, &ctx);
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
        let error = verify_completed_pcp(&source, &bio, &ctx, &files, &new.legacy).unwrap_err();
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
    let (bio, ctx) = (pipeline(), context());
    let new = build_and_open(&source, &bio, &ctx);
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
                verify_completed_pcp(&source, &bio, &ctx, &files, &new.legacy),
                Err(Error::PreservationMismatch("migration_source_mismatch"))
            );
        }
    }
}

#[test]
fn completion_bounds_binary_migration_metadata() {
    let source = SourcePcp::parse(legacy_profile("2.8", true)).unwrap();
    let (bio, ctx) = (pipeline(), context());
    let mut new = build_and_open(&source, &bio, &ctx);
    new.files
        .insert("migration.pb".into(), vec![0; 1024 * 1024 + 1]);
    assert_eq!(
        verify_completed_pcp(&source, &bio, &ctx, &new.files, &new.legacy),
        Err(Error::SizeLimit)
    );
}

#[test]
fn migration_time_must_fit_the_archive_headers() {
    // The builder writes the migration time into 32-bit gzip headers.
    let source = SourcePcp::parse(legacy_profile("2.8", true)).unwrap();
    let mut ctx = context();
    ctx.migrated_ts = u64::from(u32::MAX) + 1;
    let bio = pipeline();
    let result = with_build_request(
        &source,
        &bio,
        &ctx,
        OutputKeys::generate().recipients(),
        |request| {
            orb_pcp::build(request, &mut rand::rngs::OsRng, |_| {
                Ok::<_, std::convert::Infallible>(SIGNATURE.to_vec())
            })
        },
    )
    .unwrap();
    assert!(matches!(result, Err(orb_pcp::BuildError::Archive(_))));
}

#[test]
fn source_signature_is_required_for_mapping_and_completion() {
    for bytes in [None, Some(vec![])] {
        let mut old = legacy_profile("2.8", true);
        let source = SourcePcp::parse(old.clone()).unwrap();
        let (bio, ctx) = (pipeline(), context());
        let new = build_and_open(&source, &bio, &ctx);
        if let Some(bytes) = bytes {
            old.insert("hashes.sign".into(), bytes);
        } else {
            old.remove("hashes.sign");
        }
        let source = SourcePcp::parse(old).unwrap();
        assert_eq!(
            check_request(&source, &pipeline(), &context()).err(),
            Some(Error::MissingArtifact("hashes.sign"))
        );
        assert_eq!(
            verify_completed_pcp(&source, &bio, &ctx, &new.files, &new.legacy),
            Err(Error::MissingArtifact("hashes.sign"))
        );
    }
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
        let mut info = json_file(&files, "info.json");
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
        let (bio, ctx) = (pipeline(), context());
        let new = build_and_open(&source, &bio, &ctx);
        verify_completed_pcp(&source, &bio, &ctx, &new.files, &new.legacy).unwrap();
        for field in [
            "left_iris_code_aggregate_image_ids",
            "right_iris_code_aggregate_image_ids",
        ] {
            let mut files = new.files.clone();
            let mut info = json_file(&files, "info.json");
            info[field] = json!(["left-id"]);
            files.insert("info.json".into(), serde_json::to_vec(&info).unwrap());
            assert_eq!(
                verify_completed_pcp(&source, &bio, &ctx, &files, &new.legacy),
                Err(Error::PreservationMismatch("capture_metadata_changed"))
            );
        }
    }
}

#[test]
fn capture_metadata_changes_are_limited_to_the_signup_id() {
    let mut files = source_files("2.8");
    let mut info = json_file(&files, "info.json");
    // Populate all passthrough scalars, including fields absent in the basic fixture.
    let empty = serde_json::to_value(Info::default()).unwrap();
    for field in empty.as_object().unwrap().keys() {
        if !info.as_object().unwrap().contains_key(field) && !field.ends_with("_image_ids") {
            info[field] = json!(format!("source-{field}"));
        }
    }
    info["orb_public_key_certificate"] = json!("c3ludGhldGljLWNlcnRpZmljYXRl");
    info["left_ir_multiframe_image_ids"] = json!(["frame-b", "frame-a"]);
    info["right_ir_multiframe_image_ids"] = json!([]);
    info["right_iris_code_aggregate_image_ids"] = json!(["frame-c"]);
    files.insert("info.json".into(), serde_json::to_vec(&info).unwrap());
    files.insert("iris/frame-a.png".into(), b"synthetic-frame-a".to_vec());
    files.insert("iris/frame-b.png".into(), b"synthetic-frame-b".to_vec());
    let source = SourcePcp::parse(files).unwrap();
    let (bio, ctx) = (pipeline(), context());
    let new = build_and_open(&source, &bio, &ctx);
    verify_completed_pcp(&source, &bio, &ctx, &new.files, &new.legacy).unwrap();
    let source_fields = serde_json::to_value(source.info()).unwrap();
    for (field, value) in source_fields.as_object().unwrap() {
        if field == "signup_id" || field.ends_with("_salt") {
            continue;
        }
        let mut files = new.files.clone();
        let mut info = json_file(&files, "info.json");
        info[field] = if value.is_array() {
            json!(["changed"])
        } else {
            json!("123456")
        };
        files.insert("info.json".into(), serde_json::to_vec(&info).unwrap());
        assert_eq!(
            verify_completed_pcp(&source, &bio, &ctx, &files, &new.legacy),
            Err(Error::PreservationMismatch("capture_metadata_changed")),
            "{field}"
        );
    }
}

fn with_info(files: &Files, edit: impl FnOnce(&mut Value)) -> Files {
    let mut files = files.clone();
    let mut info = json_file(&files, "info.json");
    edit(&mut info);
    files.insert("info.json".into(), serde_json::to_vec(&info).unwrap());
    files
}

#[test]
fn completion_requires_the_derived_signup_id_and_well_formed_salts() {
    // 2.0 lacks country, software, commitment and device key in this profile.
    let source = SourcePcp::parse(legacy_profile("2.0", true)).unwrap();
    let (bio, ctx) = (pipeline(), context());
    let new = build_and_open(&source, &bio, &ctx);
    let fresh_salt = "0123456789abcdef0123456789abcdef";
    for (edit, reason) in [
        (
            json!({"signup_id": "synthetic-orb-signup"}),
            "signup_id_mismatch",
        ),
        (json!({"orb_id_salt": null}), "salt_invalid"),
        (json!({"orb_id_salt": "not-hex"}), "salt_invalid"),
        (json!({"orb_country_salt": fresh_salt}), "salt_invalid"),
        // Well formed, but the manifest hashes the emitted salt.
        (json!({"orb_id_salt": fresh_salt}), "manifest_hash_mismatch"),
    ] {
        let files = with_info(&new.files, |info| {
            for (field, value) in edit.as_object().unwrap() {
                match value {
                    Value::Null => {
                        info.as_object_mut().unwrap().remove(field);
                    }
                    value => info[field] = value.clone(),
                }
            }
        });
        assert_eq!(
            verify_completed_pcp(&source, &bio, &ctx, &files, &new.legacy),
            Err(Error::OutputMismatch(reason)),
            "{edit}"
        );
    }
}

#[test]
fn completion_recomputes_every_manifest_entry() {
    let source = SourcePcp::parse(legacy_profile("2.8", true)).unwrap();
    let (bio, ctx) = (pipeline(), context());
    let new = build_and_open(&source, &bio, &ctx);
    let manifest = || -> std::collections::BTreeMap<String, String> {
        serde_json::from_slice(&new.files["hashes.json"]).unwrap()
    };
    let with_manifest = |edit: &dyn Fn(&mut std::collections::BTreeMap<String, String>)| {
        let mut entries = manifest();
        edit(&mut entries);
        let mut files = new.files.clone();
        files.insert("hashes.json".into(), serde_json::to_vec(&entries).unwrap());
        files
    };
    let mut changed_output = new.files.clone();
    changed_output
        .get_mut("iris_codes.json")
        .unwrap()
        .push(b' ');
    let mut unlisted_member = new.files.clone();
    unlisted_member.insert("normalized_iris/extra.bin".into(), vec![1]);
    let mut pretty = new.files.clone();
    pretty.insert(
        "hashes.json".into(),
        serde_json::to_vec_pretty(&manifest()).unwrap(),
    );
    for (files, reason) in [
        (changed_output, "manifest_hash_mismatch"),
        (unlisted_member, "manifest_entry_missing"),
        (
            with_manifest(&|entries| {
                entries.remove("left_ir.png");
            }),
            "manifest_entry_missing",
        ),
        (
            with_manifest(&|entries| {
                entries.insert("invented.json".into(), "00".repeat(32));
            }),
            "manifest_entry_unexpected",
        ),
        (
            with_manifest(&|entries| {
                entries.insert("version".into(), "2.8".into());
            }),
            "manifest_version",
        ),
        (pretty, "manifest_not_canonical"),
        (
            {
                let mut files = new.files.clone();
                let info = serde_json::to_vec_pretty(&json_file(&files, "info.json")).unwrap();
                files.insert("info.json".into(), info);
                files
            },
            "info_json_not_canonical",
        ),
    ] {
        assert_eq!(
            verify_completed_pcp(&source, &bio, &ctx, &files, &new.legacy),
            Err(Error::OutputMismatch(reason)),
            "{reason}"
        );
    }
}

#[test]
fn completion_checks_migration_metadata_against_the_mapping() {
    let source = SourcePcp::parse(legacy_profile("2.8", true)).unwrap();
    let (bio, ctx) = (pipeline(), context());
    let new = build_and_open(&source, &bio, &ctx);
    let mut files = new.files.clone();
    let mut migration = Migration::decode(files["migration.pb"].as_slice()).unwrap();
    migration.tee_version = Some("other-tee".into());
    files.insert("migration.pb".into(), migration.encode_to_vec());
    assert_eq!(
        verify_completed_pcp(&source, &bio, &ctx, &files, &new.legacy),
        Err(Error::OutputMismatch("migration_metadata_mismatch"))
    );
}
