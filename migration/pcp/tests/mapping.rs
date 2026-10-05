use di_migration_pcp::*;
use orb_pcp_defs::{prost::Message, v1::Migration};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

mod support;
use support::{
    OutputKeys, SIGNATURE, build_and_open, check_request, context, open, pipeline, source_files,
};

fn edit_info(files: &mut Files, f: impl FnOnce(&mut serde_json::Value)) {
    let mut info = serde_json::from_slice(&files["info.json"]).unwrap();
    f(&mut info);
    files.insert("info.json".into(), serde_json::to_vec(&info).unwrap());
}

#[test]
fn all_supported_versions_preserve_capture_and_fill_absence() {
    for version in [
        "0.2", "0.3", "2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8",
    ] {
        let files = source_files(version);
        let source = SourcePcp::parse(files.clone()).unwrap();
        assert_eq!(source.version().as_str(), version);
        assert_eq!(version.parse::<SourceVersion>().unwrap(), source.version());
        let (bio, ctx) = (pipeline(), context());
        let new = build_and_open(&source, &bio, &ctx);
        // The final check compares every preserved image and legacy file with the source.
        verify_completed_pcp(&source, &bio, &ctx, &new.files, &new.legacy).unwrap();
        for name in [
            "hashes.json",
            "hashes.sign",
            "iris_codes.json",
            "face_embeddings.json",
        ] {
            assert_eq!(new.legacy[name], files[name], "{name}");
        }
        let info: Value = serde_json::from_slice(&new.files["info.json"]).unwrap();
        assert_eq!(info["signup_id"], "synthetic-orb-signup_di_v1.2.3");
        assert_eq!(info["timestamp"], "1700000000");
        assert_eq!(info["id_commitment"], "original-commitment");
        assert_eq!(
            info["left_iris_code_aggregate_image_ids"],
            json!(["old-aggregate"])
        );
        assert_eq!(info["left_ir_multiframe_image_ids"], json!([]));
        let migration = Migration::decode(new.files["migration.pb"].as_slice()).unwrap();
        assert_eq!(
            migration,
            Migration {
                tee_version: Some("0.1.0-test".into()),
                src_signup_id: Some("synthetic-orb-signup".into()),
                source_pcp_version: Some(version.into()),
                migrated_ts: Some(1800000000),
                biometric_pipeline_version: Some("pipeline-1".into()),
            }
        );
    }
}

#[test]
fn sparse_metadata_preserves_null_empty_and_missing_semantics() {
    let mut files = source_files("0.3");
    files.insert("info.json".into(), br#"{"signup_id":"s","signup_reason":"","software_version":null,"left_ir_multiframe_image_ids":[]}"#.to_vec());
    let source = SourcePcp::parse(files).unwrap();
    let json = serde_json::to_value(source.info()).unwrap();
    assert_eq!(json["signup_reason"], "");
    assert!(json["software_version"].is_null());
    assert!(json["orb_country"].is_null());
    assert_eq!(json["left_ir_multiframe_image_ids"], json!([]));
    assert!(json["right_ir_multiframe_image_ids"].is_null());
    assert_eq!(
        check_request(&source, &pipeline(), &context()).err(),
        Some(Error::MissingCaptureField("timestamp"))
    );
}

#[test]
fn builder_required_capture_fields_are_never_invented() {
    for field in ["signup_reason", "orb_id", "operator_id", "timestamp"] {
        let mut files = source_files("2.8");
        edit_info(&mut files, |i| {
            i.as_object_mut().unwrap().remove(field);
        });
        let source = SourcePcp::parse(files).unwrap();
        assert_eq!(
            check_request(&source, &pipeline(), &context()).err(),
            Some(Error::MissingCaptureField(field))
        );
    }
}

#[test]
fn missing_primary_and_thumbnail_ids_stay_absent_in_the_new_pcp() {
    let mut files = source_files("2.8");
    edit_info(&mut files, |i| {
        let info = i.as_object_mut().unwrap();
        for field in [
            "left_ir_image_id",
            "right_ir_image_id",
            "thumbnail_image_id",
        ] {
            info.remove(field);
        }
    });
    let source = SourcePcp::parse(files).unwrap();
    let (bio, ctx) = (pipeline(), context());
    let new = build_and_open(&source, &bio, &ctx);
    verify_completed_pcp(&source, &bio, &ctx, &new.files, &new.legacy).unwrap();
    let info: Value = serde_json::from_slice(&new.files["info.json"]).unwrap();
    for field in [
        "left_ir_image_id",
        "right_ir_image_id",
        "thumbnail_image_id",
    ] {
        assert!(info.get(field).is_none(), "{field}");
    }
}

#[test]
fn certificate_must_be_canonical_base64() {
    for certificate in ["YQ", "YR==", "not base64", "c3ludGhldGljLWNlcnRpZmljYXRl\n"] {
        let mut files = source_files("2.8");
        edit_info(&mut files, |i| {
            i["orb_public_key_certificate"] = json!(certificate)
        });
        let source = SourcePcp::parse(files).unwrap();
        assert_eq!(
            check_request(&source, &pipeline(), &context()).err(),
            Some(Error::InvalidField("orb_public_key_certificate")),
            "{certificate}"
        );
    }
}

#[test]
fn absent_or_empty_primary_images_fail_by_presence_not_version() {
    for version in [
        "0.2", "0.3", "2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8",
    ] {
        for name in [
            "iris/left_ir.png",
            "iris/right_ir.png",
            "face/thumbnail.png",
        ] {
            for empty in [false, true] {
                let mut files = source_files(version);
                if empty {
                    files.insert(name.into(), vec![]);
                } else {
                    files.remove(name);
                }
                let source = SourcePcp::parse(files).unwrap();
                assert_eq!(
                    source.pipeline_inputs().err().unwrap(),
                    Error::MissingArtifact(name)
                );
                assert_eq!(
                    check_request(&source, &pipeline(), &context())
                        .err()
                        .unwrap(),
                    Error::MissingArtifact(name)
                );
            }
        }
    }
}

#[test]
fn legacy_biometrics_and_opened_thermal_images_are_preserved_exactly() {
    let mut files = source_files("2.5");
    files.insert(
        "iris_code_shares_0.json".into(),
        b"{\"IRIS_shares_version\":\"old\"}".to_vec(),
    );
    files.insert("face_ir_and_thermal/face_ir.png".into(), vec![1, 2]);
    files.insert(
        "normalized_iris/left_normalized_image.bin".into(),
        b"obsolete".to_vec(),
    );
    files.insert("di_iris_embeddings.pb".into(), b"obsolete".to_vec());
    let source = SourcePcp::parse(files.clone()).unwrap();
    let (bio, ctx) = (pipeline(), context());
    let new = build_and_open(&source, &bio, &ctx);
    // Also rejects any legacy or raw-image member the source lacks.
    verify_completed_pcp(&source, &bio, &ctx, &new.files, &new.legacy).unwrap();
    for name in ["iris_code_shares_0.json", "di_iris_embeddings.pb"] {
        assert_eq!(new.legacy[name], files[name], "{name}");
    }
    assert_eq!(new.files["face_ir_and_thermal/face_ir.png"], [1, 2]);
    // Fresh normalization replaces the source's.
    assert_eq!(
        new.files["normalized_iris/left_normalized_image.bin"],
        [1; 16]
    );
}

#[test]
fn malformed_fields_versions_and_duplicates_are_rejected_without_payloads() {
    for timestamp in [
        json!(-1),
        json!(1.5),
        json!(true),
        json!("private-invalid-time"),
        json!("18446744073709551616"),
        json!("01700000000"),
        json!("+1700000000"),
        json!(""),
    ] {
        let mut files = source_files("0.2");
        edit_info(&mut files, |i| i["timestamp"] = timestamp);
        let error = SourcePcp::parse(files).err().unwrap();
        assert!(matches!(
            error,
            Error::InvalidJson {
                artifact: "info.json",
                ..
            }
        ));
        assert!(!format!("{error:?}").contains("private-invalid-time"));
    }
    for version in [
        // Migrated packages cannot be migrated again.
        OUTPUT_VERSION.label(),
        "3.0",
        "2.99",
        "0.1",
        "1.0",
        "2.10",
        "",
        "V2_8",
        "2.8.0",
        " 2.8",
        "2.8 ",
    ] {
        assert_eq!(
            version.parse::<SourceVersion>(),
            Err(Error::UnsupportedVersion)
        );
        let mut files = source_files("2.8");
        files.insert(
            "hashes.json".into(),
            serde_json::to_vec(&json!({"version":version})).unwrap(),
        );
        assert_eq!(
            SourcePcp::parse(files).err().unwrap(),
            Error::UnsupportedVersion
        );
    }
    let mut files = source_files("2.8");
    files.insert(
        "info.json".into(),
        br#"{"signup_id":"first","signup_id":"second"}"#.to_vec(),
    );
    assert!(matches!(
        SourcePcp::parse(files).err().unwrap(),
        Error::InvalidJson { .. }
    ));
}

#[test]
fn numeric_manifest_and_large_integer_timestamp_are_exact() {
    let mut files = source_files("0.2");
    files.insert("hashes.json".into(), br#"{"version":0.2}"#.to_vec());
    edit_info(&mut files, |i| {
        i["timestamp"] = json!(18446744073709551615u64)
    });
    let source = SourcePcp::parse(files).unwrap();
    assert_eq!(source.version(), SourceVersion::V0_2);
    assert_eq!(
        source.info().timestamp.as_deref(),
        Some("18446744073709551615")
    );
    // Parsing is exact, but this capture time cannot be represented for the builder.
    assert_eq!(
        check_request(&source, &pipeline(), &context()).err(),
        Some(Error::InvalidField("timestamp"))
    );
}

#[test]
fn unknown_fields_paths_and_excessive_input_fail_explicitly() {
    for path in [
        "../outside",
        "/absolute",
        "iris//bad",
        "iris/./bad",
        "iris\\bad",
    ] {
        let mut files = source_files("2.7");
        files.insert(path.into(), vec![1]);
        assert_eq!(SourcePcp::parse(files).err().unwrap(), Error::UnsafePath);
    }
    let mut files = source_files("2.7");
    files.insert("unknown.json".into(), vec![1]);
    assert_eq!(
        SourcePcp::parse(files).err().unwrap(),
        Error::UnsupportedArtifact
    );
    let mut files = source_files("2.7");
    edit_info(&mut files, |i| i["unknown_metadata"] = json!(1));
    assert!(matches!(
        SourcePcp::parse(files).err().unwrap(),
        Error::InvalidJson { .. }
    ));
    let mut files = source_files("2.7");
    files.insert("info.json".into(), vec![b' '; 1024 * 1024 + 1]);
    assert_eq!(SourcePcp::parse(files).err().unwrap(), Error::SizeLimit);
}

#[test]
fn incomplete_and_inconsistent_pipeline_results_never_fall_back_to_old_data() {
    for case in 0..8 {
        let mut bio = pipeline();
        match case {
            0 => bio.face_embeddings.clear(),
            1 => bio.di.left = None,
            2 => bio.daugman.left.iris_code = None,
            3 => bio.daugman.right.mask_code_shares[1] = "",
            4 => bio.daugman.iris_version = None,
            5 => bio.face_embeddings[0].embedding_version = "",
            6 => bio.di.right.as_mut().unwrap().embedding_f32 = &[f32::NAN, 0.1],
            _ => bio.left_normalized.image = &[],
        }
        let source = SourcePcp::parse(source_files("2.7")).unwrap();
        assert!(check_request(&source, &bio, &context()).is_err());
    }
}

#[test]
fn builder_bridge_retains_multiframe_images_and_recipient_order() {
    let mut files = source_files("2.8");
    edit_info(&mut files, |i| {
        i["left_ir_multiframe_image_ids"] = json!(["extra"])
    });
    files.insert("iris/extra.png".into(), vec![9]);
    let source = SourcePcp::parse(files).unwrap();
    let (bio, ctx) = (pipeline(), context());
    with_build_request(
        &source,
        &bio,
        &ctx,
        OutputKeys::generate().recipients(),
        |request| {
            let orb_pcp::BiometricPolicy::Included {
                images,
                daugman,
                di,
                face_embeddings,
                ..
            } = &request.biometrics
            else {
                panic!("must include")
            };
            assert_eq!(images.left.as_ref().unwrap().multiframe[0].ir_png, &[9]);
            assert_eq!(
                images
                    .left
                    .as_ref()
                    .unwrap()
                    .primary
                    .normalized
                    .as_ref()
                    .unwrap()
                    .image,
                &[1; 16]
            );
            assert_eq!(
                daugman.left.iris_code_shares,
                ["code-0", "code-1", "code-2"]
            );
            assert_eq!(
                di.unwrap().right.as_ref().unwrap().embedding_shares[2],
                &[31, 32]
            );
            assert_eq!(face_embeddings[0].embedding, "new-face");
        },
    )
    .unwrap();
}

#[test]
fn builder_bridge_rejects_unmapped_or_duplicate_images() {
    for duplicate in [false, true] {
        let mut files = source_files("2.8");
        files.insert("iris/extra.png".into(), vec![9]);
        if duplicate {
            edit_info(&mut files, |i| {
                i["left_ir_multiframe_image_ids"] = json!(["extra", "extra"])
            });
        }
        let source = SourcePcp::parse(files).unwrap();
        assert!(check_request(&source, &pipeline(), &context()).is_err());
    }
}

#[test]
fn migration_identity_uses_source_signup_and_rejects_path_characters() {
    assert_eq!(
        generate_migration_signup_id("original", "2.0").unwrap(),
        "original_di_v2.0"
    );
    assert_eq!(
        generate_migration_signup_id("original", "3.0").unwrap(),
        "original_di_v3.0"
    );
    for model in ["", "../v1", "v1/key", "v1\n"] {
        assert!(generate_migration_signup_id("original", model).is_err());
    }
}

#[test]
fn face_outputs_retain_individual_model_versions_and_backends() {
    let mut bio = pipeline();
    bio.face_embeddings[0].embedding_inference_backend = "other-runtime";
    bio.face_embeddings.push(orb_pcp::FaceEmbedding {
        embedding: "second-face",
        embedding_type: "another-model",
        embedding_version: "face-3",
        embedding_inference_backend: "another-runtime",
    });
    let source = SourcePcp::parse(source_files("2.8")).unwrap();
    let new = build_and_open(&source, &bio, &context());
    let faces: Value = serde_json::from_slice(&new.files["face_embeddings.json"]).unwrap();
    assert_eq!(faces[0]["embedding_inference_backend"], "other-runtime");
    assert_eq!(faces[1]["embedding_version"], "face-3");
    assert_eq!(faces[1]["embedding_inference_backend"], "another-runtime");
}

#[test]
fn builder_generated_orb_captures_open_as_sources() {
    // The reader's logical paths must match the shared builder's 2.7/2.8 output.
    for (version, device_public_key, expected_version) in [
        (orb_pcp::PcpVersion::V2_7, None, SourceVersion::V2_7),
        (
            orb_pcp::PcpVersion::V2_8,
            Some("device"),
            SourceVersion::V2_8,
        ),
    ] {
        let source = SourcePcp::parse(source_files("2.8")).unwrap();
        let (bio, ctx) = (pipeline(), context());
        let keys = OutputKeys::generate();
        let mut signed_digest = None;
        let package = with_build_request(&source, &bio, &ctx, keys.recipients(), |request| {
            // Reuse the migration inputs as an Orb capture, which requires
            // fields the synthetic source lacks.
            let orb_pcp::BiometricPolicy::Included {
                images,
                thumbnail_image_id,
                left_iris_code_aggregate_image_ids,
                right_iris_code_aggregate_image_ids,
                face_embeddings,
                daugman,
                di,
            } = request.biometrics
            else {
                panic!("must include")
            };
            let info = &request.info;
            orb_pcp::build(
                &orb_pcp::BuildRequest {
                    version,
                    timestamp: request.timestamp,
                    info: orb_pcp::PackageInfo {
                        signup_id: info.signup_id,
                        signup_reason: info.signup_reason,
                        orb_id: info.orb_id,
                        operator_id: info.operator_id,
                        capture_start: info.capture_start,
                        qr_code: Some("synthetic-qr"),
                        id_commitment: info.id_commitment,
                        software_version: Some("synthetic-software"),
                        orb_country: Some("XX"),
                        orb_public_key_certificate: Some(b"synthetic-certificate"),
                        device_public_key,
                    },
                    user_public_key: request.user_public_key,
                    backend_keys: keys.recipients().backend_keys,
                    biometrics: orb_pcp::BiometricPolicy::Included {
                        images,
                        thumbnail_image_id,
                        left_iris_code_aggregate_image_ids,
                        right_iris_code_aggregate_image_ids,
                        face_embeddings,
                        daugman,
                        di,
                    },
                    migration: None,
                },
                &mut rand::rngs::OsRng,
                |digest| {
                    signed_digest = Some(*digest);
                    Ok::<_, std::convert::Infallible>(SIGNATURE.to_vec())
                },
            )
        })
        .unwrap()
        .unwrap();
        let (files, _) = open(&package, &keys);
        let digest: [u8; 32] = Sha256::digest(&files["hashes.json"]).into();
        assert_eq!(signed_digest, Some(digest));
        let opened = SourcePcp::parse(files).unwrap();
        assert_eq!(opened.version(), expected_version);
        assert_eq!(
            opened.info().device_public_key.as_deref(),
            device_public_key
        );
        let inputs = opened.pipeline_inputs().unwrap();
        assert_eq!(inputs.left_ir_png, b"synthetic-left-png");
        assert_eq!(inputs.right_ir_png, b"synthetic-right-png");
        assert_eq!(inputs.thumbnail_png, b"synthetic-face-png");
    }
}

#[test]
fn unopened_thermal_archive_requires_extraction() {
    let mut files = source_files("2.5");
    files.insert("face_ir_and_thermal.tar".into(), vec![255, 0, 1]);
    assert_eq!(
        SourcePcp::parse(files).err(),
        Some(Error::UnopenedArtifact("face_ir_and_thermal.tar"))
    );
}

#[test]
fn builder_bridge_carries_fresh_multiframe_normalization_and_rejects_unmapped_output() {
    let mut files = source_files("2.8");
    edit_info(&mut files, |i| {
        i["left_ir_multiframe_image_ids"] = json!(["extra"])
    });
    files.insert("iris/extra.png".into(), vec![9]);
    let mut bio = pipeline();
    bio.extra_normalized.insert(
        "extra".into(),
        orb_pcp::NormalizedIrisFrame {
            image: &[5; 16],
            mask: &[6; 16],
            image_resized: &[7; 8],
            mask_resized: &[8; 8],
        },
    );
    let source = SourcePcp::parse(files).unwrap();
    with_build_request(
        &source,
        &bio,
        &context(),
        OutputKeys::generate().recipients(),
        |request| {
            let orb_pcp::BiometricPolicy::Included { images, .. } = &request.biometrics else {
                panic!("must include")
            };
            let frame = &images.left.as_ref().unwrap().multiframe[0];
            assert_eq!(frame.image_id, Some("extra"));
            let normalized = frame.normalized.as_ref().unwrap();
            assert_eq!(normalized.image, &[5; 16]);
            assert_eq!(normalized.mask, &[6; 16]);
            assert_eq!(normalized.image_resized, &[7; 8]);
            assert_eq!(normalized.mask_resized, &[8; 8]);
        },
    )
    .unwrap();
    // Normalization for an image ID the source does not reference.
    let mut bio = pipeline();
    bio.extra_normalized.insert(
        "unknown".into(),
        orb_pcp::NormalizedIrisFrame {
            image: &[5; 16],
            mask: &[6; 16],
            image_resized: &[7; 8],
            mask_resized: &[8; 8],
        },
    );
    let source = SourcePcp::parse(source_files("2.8")).unwrap();
    assert_eq!(
        check_request(&source, &bio, &context()).err(),
        Some(Error::InvalidField("normalized_image_id"))
    );
}

#[test]
fn numeric_manifest_versions_are_limited_to_0_2_and_0_3() {
    for (version, expected) in [
        ("0.3", Some(SourceVersion::V0_3)),
        ("0.30", Some(SourceVersion::V0_3)),
        ("2.8", None),
        ("2.10", None),
        ("20e-1", None),
        ("3", None),
    ] {
        let mut files = source_files("2.8");
        files.insert(
            "hashes.json".into(),
            format!("{{\"version\":{version}}}").into_bytes(),
        );
        let parsed = SourcePcp::parse(files).map(|source| source.version());
        match expected {
            Some(expected) => assert_eq!(parsed, Ok(expected), "{version}"),
            None => assert_eq!(parsed, Err(Error::UnsupportedVersion), "{version}"),
        }
    }
}

#[test]
fn multiframe_ids_must_not_collide_with_builder_member_names() {
    let normalization = || orb_pcp::NormalizedIrisFrame {
        image: &[5; 16],
        mask: &[6; 16],
        image_resized: &[7; 8],
        mask_resized: &[8; 8],
    };
    let at_limit = "x".repeat(100 - "_normalized_image_blinding_factors_resized.bin".len());
    for (id, normalized, expected) in [
        (
            "left_ir",
            false,
            Some(Error::InvalidField("duplicate_image_id")),
        ),
        (
            "thumbnail",
            false,
            Some(Error::InvalidField("duplicate_image_id")),
        ),
        (
            "left",
            true,
            Some(Error::InvalidField("duplicate_image_id")),
        ),
        ("left", false, None),
        (at_limit.as_str(), true, None),
        (
            &format!("{at_limit}x"),
            true,
            Some(Error::InvalidField("multiframe_image_id")),
        ),
        (&format!("{at_limit}x"), false, None),
    ] {
        let mut files = source_files("2.8");
        edit_info(&mut files, |i| {
            i["left_ir_multiframe_image_ids"] = json!([id])
        });
        files.insert(format!("iris/{id}.png"), vec![9]);
        let mut bio = pipeline();
        if normalized {
            bio.extra_normalized.insert(id.to_owned(), normalization());
        }
        let source = SourcePcp::parse(files).unwrap();
        let ctx = context();
        match expected {
            Some(error) => assert_eq!(
                check_request(&source, &bio, &ctx).err(),
                Some(error),
                "{id}"
            ),
            None => {
                let new = build_and_open(&source, &bio, &ctx);
                verify_completed_pcp(&source, &bio, &ctx, &new.files, &new.legacy).unwrap();
            }
        }
    }
}
