use di_migration_pcp::*;
use serde_json::json;
use sha2::{Digest, Sha256};

mod support;
use support::{context, pipeline, source_files};

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
        let mapped = migrate(&source, pipeline(), context()).unwrap();
        assert_eq!(mapped.info.timestamp.as_deref(), Some("1700000000"));
        assert_eq!(mapped.info.timestamp_salt.as_deref(), Some("capture-salt"));
        assert_eq!(
            mapped.info.signup_id.as_deref(),
            Some("synthetic-orb-signup_di_v1.2.3")
        );
        assert_eq!(mapped.info.src_signup_id, source.info().signup_id);
        assert_eq!(mapped.info.src_signup_id, mapped.migration.src_signup_id);
        assert!(mapped.info.signup_id_salt.is_none());
        assert_eq!(
            mapped.info.id_commitment.as_deref(),
            Some("original-commitment")
        );
        assert!(mapped.info.orb_country.is_none());
        assert!(mapped.info.qr_code.is_none());
        assert!(mapped.info.device_public_key.is_none());
        assert!(mapped.source_backend_keys.is_none());
        assert_eq!(
            mapped.migration.source_pcp_version.as_deref(),
            Some(version)
        );
        assert_eq!(
            mapped.migration.src_signup_id.as_deref(),
            Some("synthetic-orb-signup")
        );
        assert_eq!(mapped.migration.tee_version.as_deref(), Some("0.1.0-test"));
        assert_eq!(mapped.migration.migrated_ts, Some(1800000000));
        assert_eq!(
            mapped.migration.biometric_pipeline_version.as_deref(),
            Some("pipeline-1")
        );
        assert_eq!(mapped.legacy["hashes.json"], files["hashes.json"]);
        assert_eq!(mapped.legacy["hashes.sign"], files["hashes.sign"]);
        assert!(!mapped.legacy.contains_key("info.json"));
        assert_eq!(mapped.legacy["iris_codes.json"], files["iris_codes.json"]);
        assert_eq!(
            mapped.legacy["face_embeddings.json"],
            files["face_embeddings.json"]
        );
        assert_eq!(
            mapped.raw_images["iris/left_ir.png"],
            files["iris/left_ir.png"]
        );
        assert_eq!(
            mapped.info.left_iris_code_aggregate_image_ids,
            Some(vec!["old-aggregate".into()])
        );
        assert!(mapped.info.left_ir_multiframe_image_ids.is_none());
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
    let mapped = migrate(&source, pipeline(), context()).unwrap();
    assert_eq!(
        mapped.with_builder_biometrics(|_| ()).err().unwrap(),
        Error::InvalidField("left_ir_image_id")
    );
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
                    migrate(&source, pipeline(), context()).err().unwrap(),
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
    let mapped = migrate(
        &SourcePcp::parse(files.clone()).unwrap(),
        pipeline(),
        context(),
    )
    .unwrap();
    assert_eq!(
        mapped.legacy["iris_code_shares_0.json"],
        files["iris_code_shares_0.json"]
    );
    assert!(!mapped.legacy.contains_key("iris_code_shares_1.json"));
    assert_eq!(
        mapped.legacy["di_iris_embeddings.pb"],
        files["di_iris_embeddings.pb"]
    );
    assert!(!mapped.legacy.contains_key("face_ir_and_thermal.tar"));
    assert!(
        !mapped
            .legacy
            .contains_key("normalized_iris/left_normalized_image.bin")
    );
    assert_eq!(
        mapped.raw_images["face_ir_and_thermal/face_ir.png"],
        vec![1, 2]
    );
    assert!(!mapped.raw_images.contains_key("di_iris_embeddings.pb"));
}

#[test]
fn backend_key_roles_and_missing_members_remain_optional() {
    let mut files = source_files("2.5");
    files.insert(
        "backend_keys.json".into(),
        br#"{"iris":{"public_key":"pk"},"tier2":{"encrypted_private_key":"envelope"}}"#.to_vec(),
    );
    let source = SourcePcp::parse(files).unwrap();
    let keys = source.backend_keys().unwrap();
    assert!(keys.face.is_none());
    assert!(keys.iris.as_ref().unwrap().encrypted_private_key.is_none());
    assert_eq!(
        keys.tier2
            .as_ref()
            .unwrap()
            .encrypted_private_key
            .as_deref(),
        Some("envelope")
    );
}

#[test]
fn device_binding_is_preserved_with_its_salt() {
    for key in [None, Some("device-1")] {
        let mut files = source_files("2.8");
        edit_info(&mut files, |i| {
            i["device_public_key"] = json!(key);
            i["device_public_key_salt"] = json!(key.map(|_| "device-salt"));
        });
        let source = SourcePcp::parse(files).unwrap();
        let mapped = migrate(&source, pipeline(), context()).unwrap();
        assert_eq!(
            mapped.info.device_public_key,
            source.info().device_public_key
        );
        assert_eq!(
            mapped.info.device_public_key_salt,
            source.info().device_public_key_salt
        );
    }
}

#[test]
fn malformed_fields_versions_and_duplicates_are_rejected_without_payloads() {
    for timestamp in [
        json!(-1),
        json!(1.5),
        json!(true),
        json!("private-invalid-time"),
        json!("18446744073709551616"),
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
        "3.0", "2.9", "2.99", "0.1", "1.0", "2.10", "", "V2_8", "2.8.0", " 2.8", "2.8 ",
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
    assert_eq!(
        source.info().timestamp.as_deref(),
        Some("18446744073709551615")
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
            4 => bio.di.model_version = "different",
            5 => bio.face_embeddings[0].embedding_version = "",
            6 => bio.di.right.as_mut().unwrap().embedding_f32 = &[f32::NAN, 0.1],
            _ => bio.left_normalized.image = &[],
        }
        assert!(
            migrate(
                &SourcePcp::parse(source_files("2.7")).unwrap(),
                bio,
                context()
            )
            .is_err()
        );
    }
}

#[test]
fn builder_bridge_retains_multiframe_images_and_recipient_order() {
    let mut files = source_files("2.8");
    edit_info(&mut files, |i| {
        i["left_ir_multiframe_image_ids"] = json!(["extra"])
    });
    files.insert("iris/extra.png".into(), vec![9]);
    let mapped = migrate(&SourcePcp::parse(files).unwrap(), pipeline(), context()).unwrap();
    mapped
        .with_builder_biometrics(|policy| {
            let orb_pcp::BiometricPolicy::Included {
                images,
                daugman,
                di,
                face_embeddings,
                ..
            } = policy
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
        })
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
        let mapped = migrate(&SourcePcp::parse(files).unwrap(), pipeline(), context()).unwrap();
        assert!(mapped.with_builder_biometrics(|_| ()).is_err());
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
fn normalized_fields_convert_to_shared_generated_types() {
    use orb_pcp_defs::prost::Message;
    let source = SourcePcp::parse(source_files("0.3")).unwrap();
    let shared: orb_pcp_defs::v1::Info = source.info().clone().into();
    assert_eq!(shared.timestamp.as_deref(), Some("1700000000"));
    assert!(shared.orb_country.is_none());
    assert!(shared.left_ir_multiframe_image_ids.is_empty());
    let decoded = orb_pcp_defs::v1::Info::decode(shared.encode_to_vec().as_slice()).unwrap();
    assert!(decoded == shared);
    let json = serde_json::to_value(&shared).unwrap();
    assert!(json.get("signup_id").is_some());
    assert!(json.get("signupId").is_none());
    let keys: orb_pcp_defs::v1::BackendKeys = BackendKeys {
        tier2: Some(BackendKey {
            public_key: Some("synthetic".into()),
            encrypted_private_key: None,
        }),
        ..Default::default()
    }
    .into();
    assert!(keys.iris.is_none());
    assert_eq!(keys.tier2.unwrap().public_key.as_deref(), Some("synthetic"));
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
    assert!(
        migrate(
            &SourcePcp::parse(source_files("2.8")).unwrap(),
            bio,
            context()
        )
        .is_ok()
    );
}

#[test]
fn mapped_biometrics_build_and_decrypt_using_shared_builder() {
    // Existing producer formats only: upstream has no v2.9 envelope yet.
    use alkali::asymmetric::seal::curve25519xsalsa20poly1305 as sealedbox;
    use std::io::Read;
    for (version, device_public_key, expected_version) in [
        (orb_pcp::PcpVersion::V2_7, None, SourceVersion::V2_7),
        (
            orb_pcp::PcpVersion::V2_8,
            Some("device"),
            SourceVersion::V2_8,
        ),
    ] {
        let mapped = migrate(
            &SourcePcp::parse(source_files("2.8")).unwrap(),
            pipeline(),
            context(),
        )
        .unwrap();
        let pair = sealedbox::Keypair::generate().unwrap();
        let key = || orb_pcp::BackendKey {
            public_key: &pair.public_key,
            encrypted_private_key: "synthetic-envelope",
        };
        let mut signed_digest = None;
        let package = mapped
            .with_builder_biometrics(|biometrics| {
                orb_pcp::build(
                    &orb_pcp::BuildRequest {
                        version,
                        timestamp: 1800000000,
                        info: orb_pcp::PackageInfo {
                            signup_id: mapped.info.signup_id.as_deref().unwrap(),
                            signup_reason: "test",
                            orb_id: "orb",
                            operator_id: "operator",
                            capture_start: std::time::UNIX_EPOCH
                                + std::time::Duration::from_secs(1700000000),
                            qr_code: "test",
                            id_commitment: "test",
                            software_version: "test",
                            orb_country: "test",
                            orb_public_key_certificate: b"synthetic-certificate",
                            device_public_key,
                        },
                        user_public_key: &pair.public_key,
                        backend_keys: orb_pcp::BackendKeys {
                            iris: key(),
                            normalized_iris: key(),
                            face: key(),
                            tier2: key(),
                        },
                        biometrics,
                    },
                    &mut rand::rngs::OsRng,
                    |digest| {
                        signed_digest = Some(*digest);
                        Ok::<_, std::convert::Infallible>(b"test-signature".to_vec())
                    },
                )
            })
            .unwrap()
            .unwrap();
        let mut plaintext = vec![0; package.tier0.len() - sealedbox::OVERHEAD_LENGTH];
        sealedbox::decrypt(&package.tier0, &pair, &mut plaintext).unwrap();
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(&plaintext[..]));
        let mut files = Files::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap().to_str().unwrap().to_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            files.insert(name, bytes);
        }
        let digest: [u8; 32] = Sha256::digest(&files["hashes.json"]).into();
        assert_eq!(signed_digest, Some(digest));
        let face: serde_json::Value =
            serde_json::from_slice(&files["face_embeddings.json"]).unwrap();
        assert_eq!(face[0]["embedding"], "new-face");
        let iris: serde_json::Value = serde_json::from_slice(&files["iris_codes.json"]).unwrap();
        assert_eq!(iris["IRIS_version"], "iris-1");
        assert_eq!(iris["left_iris_code"], "new-code");
        assert!(!package.tier1.is_empty() && !package.tier2.is_empty());
        // Verify actual inner member names produced by the shared builder before adding
        // the logical archive prefixes required by SourcePcp.
        for prefix in ["iris", "face", "normalized_iris", "face_ir_and_thermal"] {
            let encrypted = files.remove(&format!("{prefix}.tar")).unwrap();
            let mut plain = vec![0; encrypted.len() - sealedbox::OVERHEAD_LENGTH];
            sealedbox::decrypt(&encrypted, &pair, &mut plain).unwrap();
            let mut inner = tar::Archive::new(plain.as_slice());
            for entry in inner.entries().unwrap() {
                let mut entry = entry.unwrap();
                let name = entry.path().unwrap().to_str().unwrap().to_owned();
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes).unwrap();
                assert!(files.insert(format!("{prefix}/{name}"), bytes).is_none());
            }
        }
        let opened = SourcePcp::parse(files).unwrap();
        assert_eq!(opened.version(), expected_version);
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
    let mut mapped = migrate(&SourcePcp::parse(files).unwrap(), bio, context()).unwrap();
    mapped
        .with_builder_biometrics(|policy| {
            let orb_pcp::BiometricPolicy::Included { images, .. } = policy else {
                panic!("must include")
            };
            let frame = &images.left.as_ref().unwrap().multiframe[0];
            assert_eq!(frame.image_id, "extra");
            let normalized = frame.normalized.as_ref().unwrap();
            assert_eq!(normalized.image, &[5; 16]);
            assert_eq!(normalized.mask, &[6; 16]);
            assert_eq!(normalized.image_resized, &[7; 8]);
            assert_eq!(normalized.mask_resized, &[8; 8]);
        })
        .unwrap();
    let frame = mapped.biometrics.extra_normalized.remove("extra").unwrap();
    mapped
        .biometrics
        .extra_normalized
        .insert("unknown".into(), frame);
    assert_eq!(
        mapped.with_builder_biometrics(|_| ()).err(),
        Some(Error::InvalidField("normalized_image_id"))
    );
    let source = SourcePcp::parse(source_files("2.8")).unwrap();
    assert_eq!(
        migrate(&source, mapped.biometrics, context()).err(),
        Some(Error::InvalidField("normalized_image_id"))
    );
}
