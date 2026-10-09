use di_migration_pcp::*;
use orb_pcp_defs::{
    prost::Message,
    v1::{self, Migration},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

mod support;
use support::{
    FRAME_A, FRAME_B, IRIS_CODES, NEW_SIGNUP_ID, OutputKeys, SIGNATURE, build_and_open,
    check_request, context, iris_code_share, open, pipeline, source_files,
};

const VERSIONS: [&str; 11] = [
    "0.2", "0.3", "2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8",
];

fn edit_info(files: &mut Files, f: impl FnOnce(&mut serde_json::Value)) {
    let mut info = serde_json::from_slice(&files["info.json"]).unwrap();
    f(&mut info);
    files.insert("info.json".into(), serde_json::to_vec(&info).unwrap());
}

fn di<'a>(bio: &'a mut PreparedBiometrics<'static>) -> &'a mut v1::DiIrisEmbeddingV1 {
    bio.di_embeddings.embedding_v1.as_mut().unwrap()
}

fn di_share<'a>(
    bio: &'a mut PreparedBiometrics<'static>,
    index: usize,
) -> &'a mut v1::DiIrisEmbeddingShareV1 {
    bio.di_embedding_shares[index].share_v1.as_mut().unwrap()
}

fn frame(fill: u8) -> orb_pcp::NormalizedIrisFrame<'static> {
    let image: &'static [u8] = Box::leak(vec![fill; 16].into_boxed_slice());
    orb_pcp::NormalizedIrisFrame {
        image,
        mask: image,
        image_resized: &image[..8],
        mask_resized: &image[..8],
    }
}

#[test]
fn all_supported_versions_preserve_capture_and_fill_absence() {
    for version in VERSIONS {
        let files = source_files(version);
        let source = SourcePcp::parse(files.clone()).unwrap();
        assert_eq!(source.version().as_str(), version);
        assert_eq!(version.parse::<SourceVersion>().unwrap(), source.version());
        let (bio, ctx) = (pipeline(), context());
        let new = build_and_open(&source, &bio, &ctx);
        // The final check compares every preserved image and iris code file with the source.
        verify_completed_pcp(&source, &bio, &ctx, &new.files).unwrap();
        let info: Value = serde_json::from_slice(&new.files["info.json"]).unwrap();
        assert_eq!(info["signup_id"], NEW_SIGNUP_ID);
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
                tee_software_version: Some("0.1.0-test".into()),
                src_signup_id: Some("synthetic-orb-signup".into()),
                source_pcp_version: Some(version.into()),
                migrated_ts: Some(1800000000),
                biometric_pipeline_version: Some("pipeline-1".into()),
            }
        );
    }
}

#[test]
fn only_signup_and_orb_ids_are_required_capture_fields() {
    let mut files = source_files("0.3");
    files.insert(
        "info.json".into(),
        br#"{"signup_id":"s","orb_id":"o","signup_reason":"","software_version":null,"left_ir_multiframe_image_ids":null}"#.to_vec(),
    );
    let source = SourcePcp::parse(files).unwrap();
    let info = source.info();
    assert_eq!(info.signup_reason.as_deref(), Some(""));
    assert_eq!(info.software_version, None);
    assert_eq!(info.timestamp, None);
    assert!(info.left_ir_multiframe_image_ids.is_empty());
    let (bio, ctx) = (pipeline(), context());
    let new = build_and_open(&source, &bio, &ctx);
    verify_completed_pcp(&source, &bio, &ctx, &new.files).unwrap();
    let info: v1::Info = serde_json::from_slice(&new.files["info.json"]).unwrap();
    assert_eq!(info.operator_id, None);
    assert_eq!(info.timestamp, None);

    for field in ["signup_id", "orb_id"] {
        for value in [None, Some(Value::Null), Some(json!(""))] {
            let mut files = source_files("2.8");
            edit_info(&mut files, |i| match &value {
                Some(value) => i[field] = value.clone(),
                None => {
                    i.as_object_mut().unwrap().remove(field);
                }
            });
            assert_eq!(
                SourcePcp::parse(files).err(),
                Some(Error::MissingCaptureField(field)),
                "{field} {value:?}"
            );
        }
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
    verify_completed_pcp(&source, &bio, &ctx, &new.files).unwrap();
    // Read through the shared type, as consumers do.
    let info: v1::Info = serde_json::from_slice(&new.files["info.json"]).unwrap();
    assert_eq!(info.left_ir_image_id, None);
    assert_eq!(info.right_ir_image_id, None);
    assert_eq!(info.thumbnail_image_id, None);
}

#[test]
fn capture_values_are_written_as_the_source_has_them() {
    let mut files = source_files("2.8");
    edit_info(&mut files, |i| {
        i["timestamp"] = json!("01700000000");
        i["orb_public_key_certificate"] = json!("not base64\n");
    });
    let source = SourcePcp::parse(files).unwrap();
    let (bio, ctx) = (pipeline(), context());
    let new = build_and_open(&source, &bio, &ctx);
    verify_completed_pcp(&source, &bio, &ctx, &new.files).unwrap();
    let info: v1::Info = serde_json::from_slice(&new.files["info.json"]).unwrap();
    assert_eq!(info.timestamp.as_deref(), Some("01700000000"));
    assert_eq!(
        info.orb_public_key_certificate.as_deref(),
        Some("not base64\n")
    );
}

#[test]
fn fields_outside_the_shared_schema_do_not_block_migration() {
    let mut files = source_files("2.8");
    edit_info(&mut files, |i| {
        i["latitude"] = json!(1.5);
        i["latitude_salt"] = json!("salt");
    });
    let source = SourcePcp::parse(files).unwrap();
    let (bio, ctx) = (pipeline(), context());
    let new = build_and_open(&source, &bio, &ctx);
    verify_completed_pcp(&source, &bio, &ctx, &new.files).unwrap();
}

#[test]
fn absent_or_empty_pipeline_images_fail_by_presence_not_version() {
    for version in VERSIONS {
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
                assert_eq!(
                    SourcePcp::parse(files).err(),
                    Some(Error::MissingArtifact(name))
                );
            }
        }
    }
    let source = SourcePcp::parse(source_files("2.8")).unwrap();
    let inputs = source.pipeline_inputs();
    assert_eq!(inputs.left_ir_png, b"synthetic-left-png");
    assert_eq!(inputs.right_ir_png, b"synthetic-right-png");
    assert_eq!(inputs.thumbnail_png, b"synthetic-face-png");
}

#[test]
fn iris_code_files_are_carried_unchanged_or_left_out() {
    let mut files = source_files("2.5");
    files.remove("iris_codes.json");
    files.remove("iris_code_shares_1.json");
    let source = SourcePcp::parse(files.clone()).unwrap();
    let (bio, ctx) = (pipeline(), context());
    let new = build_and_open(&source, &bio, &ctx);
    verify_completed_pcp(&source, &bio, &ctx, &new.files).unwrap();
    for name in ["iris_code_shares_0.json", "iris_code_shares_2.json"] {
        assert_eq!(new.files[name], files[name], "{name}");
    }
    let manifest: Value = serde_json::from_slice(&new.files["hashes.json"]).unwrap();
    for name in ["iris_codes.json", "iris_code_shares_1.json"] {
        assert!(!new.files.contains_key(name), "{name}");
        assert!(manifest.get(name).is_none(), "{name}");
    }

    let mut files = source_files("2.8");
    files.insert("iris_codes.json".into(), b"{\"IRIS_version\":".to_vec());
    assert!(matches!(
        SourcePcp::parse(files).err(),
        Some(Error::InvalidJson {
            artifact: "iris_codes.json",
            ..
        })
    ));
}

#[test]
fn replaced_outputs_are_not_carried_and_opened_thermal_images_are() {
    let mut files = source_files("2.5");
    files.insert("face_ir_and_thermal/face_ir.png".into(), vec![1, 2]);
    files.insert(
        "normalized_iris/left_normalized_image.bin".into(),
        b"obsolete".to_vec(),
    );
    files.insert("di_iris_embeddings.pb".into(), b"obsolete".to_vec());
    let source = SourcePcp::parse(files).unwrap();
    let (bio, ctx) = (pipeline(), context());
    let new = build_and_open(&source, &bio, &ctx);
    verify_completed_pcp(&source, &bio, &ctx, &new.files).unwrap();
    assert_eq!(new.files["face_ir_and_thermal/face_ir.png"], [1, 2]);
    // Fresh outputs replace the source's.
    assert_eq!(
        new.files["normalized_iris/left_normalized_image.bin"],
        [1; 16]
    );
    assert_eq!(
        new.files["di_iris_embeddings.pb"],
        bio.di_embeddings.encode_to_vec()
    );
}

#[test]
fn malformed_fields_versions_and_duplicates_are_rejected_without_payloads() {
    for timestamp in [json!(-1), json!(1.5), json!(true)] {
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
    }
    let mut files = source_files("2.8");
    edit_info(&mut files, |i| i["orb_id"] = json!(["private-orb"]));
    let error = SourcePcp::parse(files).err().unwrap();
    assert!(matches!(error, Error::InvalidJson { .. }));
    assert!(!format!("{error:?}").contains("private-orb"));
    for version in [
        "3.0", "2.99", "0.1", "1.0", "2.10", "", "V2_8", "2.8.0", " 2.8", "2.8 ",
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
        br#"{"signup_id":"first","signup_id":"second","orb_id":"o"}"#.to_vec(),
    );
    assert!(matches!(
        SourcePcp::parse(files).err().unwrap(),
        Error::InvalidJson { .. }
    ));
}

#[test]
fn migrated_packages_cannot_be_migrated_again() {
    let source = SourcePcp::parse(source_files("2.8")).unwrap();
    let new = build_and_open(&source, &pipeline(), &context());
    assert_eq!(
        SourcePcp::parse(new.files).err(),
        Some(Error::UnsupportedArtifact)
    );
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
    let (bio, ctx) = (pipeline(), context());
    let new = build_and_open(&source, &bio, &ctx);
    verify_completed_pcp(&source, &bio, &ctx, &new.files).unwrap();
}

#[test]
fn unknown_files_paths_and_excessive_input_fail_explicitly() {
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
    files.insert("info.json".into(), vec![b' '; 1024 * 1024 + 1]);
    assert_eq!(SourcePcp::parse(files).err().unwrap(), Error::SizeLimit);
}

#[test]
fn incomplete_and_inconsistent_pipeline_results_never_fall_back_to_old_data() {
    type Edit = fn(&mut PreparedBiometrics<'static>);
    let cases: [(Edit, &str); 14] = [
        (|bio| bio.face_embeddings.clear(), "face_embeddings"),
        (
            |bio| bio.face_embeddings[0].embedding_version = None,
            "face_embedding_version",
        ),
        (
            |bio| bio.biometric_pipeline_version.clear(),
            "biometric_pipeline_version",
        ),
        (|bio| bio.di_embeddings.embedding_v1 = None, "di_embeddings"),
        (|bio| di(bio).model_version.clear(), "di_model_version"),
        (
            |bio| {
                di(bio).right_embedding.pop();
            },
            "di_embeddings",
        ),
        (
            |bio| di(bio).left_embedding_f32[0] = f32::NAN,
            "di_embeddings",
        ),
        (
            |bio| di(bio).left_mirror_embedding[0] = 128,
            "di_embeddings",
        ),
        (
            |bio| bio.di_embedding_shares[1].share_v1 = None,
            "di_embedding_shares",
        ),
        (
            |bio| di_share(bio, 2).model_version = "other".into(),
            "di_embedding_shares",
        ),
        (
            |bio| di_share(bio, 0).embedding_version = "other".into(),
            "di_embedding_shares",
        ),
        (
            |bio| di_share(bio, 1).shares_version = "other".into(),
            "di_embedding_shares",
        ),
        (
            |bio| di_share(bio, 0).right_share[1] = 65536,
            "di_embedding_shares",
        ),
        (|bio| bio.left_normalized.image = &[], "normalized_iris"),
    ];
    // Unchanged pipeline output passes.
    let mut bio = pipeline();
    di(&mut bio).left_mirror_embedding[0] = -128;
    di_share(&mut bio, 0).right_share[1] = 65535;
    let source = SourcePcp::parse(source_files("2.7")).unwrap();
    check_request(&source, &bio, &context()).unwrap();
    for (edit, field) in cases {
        let mut bio = pipeline();
        edit(&mut bio);
        assert_eq!(
            check_request(&source, &bio, &context()),
            Err(Error::InvalidField(field)),
            "{field}"
        );
    }
}

#[test]
fn builder_bridge_retains_multiframe_images_and_recipient_order() {
    let mut files = source_files("2.8");
    edit_info(&mut files, |i| {
        i["left_ir_multiframe_image_ids"] = json!([FRAME_A])
    });
    files.insert(format!("iris/{FRAME_A}.png"), vec![9]);
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
                iris_code_shares,
                di_embedding_shares,
                face_embeddings,
                ..
            } = &request.biometrics
            else {
                panic!("must include")
            };
            assert_eq!(images.left.multiframe[0].ir_png, &[9]);
            assert_eq!(images.left.multiframe[0].image_id.to_string(), FRAME_A);
            assert_eq!(images.left.primary.normalized.image, &[1; 16]);
            assert_eq!(
                iris_code_shares[2]
                    .unwrap()
                    .left_iris_code_shares
                    .as_deref(),
                Some("old-share-2")
            );
            assert_eq!(
                di_embedding_shares[2].share_v1.as_ref().unwrap().left_share,
                [31, 32]
            );
            assert_eq!(face_embeddings[0].embedding.as_deref(), Some("new-face"));
        },
    )
    .unwrap();
}

#[test]
fn builder_bridge_rejects_unmapped_or_duplicate_images() {
    let mut files = source_files("2.8");
    files.insert(format!("iris/{FRAME_A}.png"), vec![9]);
    let source = SourcePcp::parse(files.clone()).unwrap();
    assert_eq!(
        check_request(&source, &pipeline(), &context()),
        Err(Error::UnmappedImage)
    );
    for (left, right) in [
        (json!([FRAME_A, FRAME_A]), json!([])),
        (json!([FRAME_A]), json!([FRAME_A])),
    ] {
        let mut files = files.clone();
        edit_info(&mut files, |i| {
            i["left_ir_multiframe_image_ids"] = left;
            i["right_ir_multiframe_image_ids"] = right;
        });
        let source = SourcePcp::parse(files).unwrap();
        assert_eq!(
            check_request(&source, &pipeline(), &context()),
            Err(Error::InvalidField("duplicate_image_id"))
        );
    }
}

#[test]
fn multiframe_ids_must_be_canonical_image_ids() {
    for (id, valid) in [
        (FRAME_A, true),
        // The same ID as a hyphenated or uppercase UUID.
        ("0012a0b1-c2d3-e4f5-a6b7-c8d901000000", false),
        ("0012A0B1C2D3E4F5A6B7C8D901000000", false),
        // An unknown region byte would print as 0xff.
        ("0020a0b1c2d3e4f5a6b7c8d901000000", false),
        ("extra", false),
    ] {
        let mut files = source_files("2.8");
        edit_info(&mut files, |i| {
            i["left_ir_multiframe_image_ids"] = json!([id])
        });
        files.insert(format!("iris/{id}.png"), vec![9]);
        let source = SourcePcp::parse(files).unwrap();
        let result = check_request(&source, &pipeline(), &context());
        if valid {
            result.unwrap();
        } else {
            assert_eq!(
                result,
                Err(Error::InvalidField("multiframe_image_id")),
                "{id}"
            );
        }
    }
}

#[test]
fn the_new_signup_id_comes_from_the_context() {
    let ctx = MigrationContext::new("0.1.0-test".into(), 1800000000, S3Region::EuCentral1);
    let other = MigrationContext::new("0.1.0-test".into(), 1800000000, S3Region::EuCentral1);
    assert_ne!(ctx.signup_id, other.signup_id);
    let source = SourcePcp::parse(source_files("2.8")).unwrap();
    let bio = pipeline();
    let new = build_and_open(&source, &bio, &ctx);
    verify_completed_pcp(&source, &bio, &ctx, &new.files).unwrap();
    let info: v1::Info = serde_json::from_slice(&new.files["info.json"]).unwrap();
    assert_eq!(info.signup_id, Some(ctx.signup_id.to_string()));
    assert_eq!(
        verify_completed_pcp(&source, &bio, &other, &new.files),
        Err(Error::OutputMismatch("signup_id_mismatch"))
    );

    // The context must not reuse the source signup ID.
    let mut files = source_files("2.8");
    edit_info(&mut files, |i| i["signup_id"] = json!(NEW_SIGNUP_ID));
    let source = SourcePcp::parse(files).unwrap();
    assert_eq!(
        check_request(&source, &bio, &context()),
        Err(Error::InvalidField("signup_id"))
    );
}

#[test]
fn face_outputs_retain_individual_model_versions_and_backends() {
    let mut bio = pipeline();
    bio.face_embeddings[0].embedding_inference_backend = Some("other-runtime".into());
    bio.face_embeddings.push(v1::FaceEmbedding {
        embedding: Some("second-face".into()),
        embedding_type: Some("another-model".into()),
        embedding_version: Some("face-3".into()),
        embedding_inference_backend: Some("another-runtime".into()),
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
    // The reader's logical paths must match the shared builder's output.
    let source = SourcePcp::parse(source_files("2.8")).unwrap();
    let (bio, ctx) = (pipeline(), context());
    let keys = OutputKeys::generate();
    let mut signed_digest = None;
    let package = with_build_request(&source, &bio, &ctx, keys.recipients(), |request| {
        // Reuse the migration inputs as an Orb capture.
        let orb_pcp::BiometricPolicy::Included {
            images,
            face_embeddings,
            iris_codes,
            iris_code_shares,
            di_embeddings,
            di_embedding_shares,
        } = request.biometrics
        else {
            panic!("must include")
        };
        let info = v1::Info {
            device_public_key: Some("device".into()),
            ..request.info.clone()
        };
        orb_pcp::build(
            &orb_pcp::BuildRequest {
                timestamp: request.timestamp,
                info: &info,
                user_public_key: request.user_public_key,
                backend_keys: keys.recipients().backend_keys,
                biometrics: orb_pcp::BiometricPolicy::Included {
                    images,
                    face_embeddings,
                    iris_codes,
                    iris_code_shares,
                    di_embeddings,
                    di_embedding_shares,
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
    let files = open(&package, &keys);
    let digest: [u8; 32] = Sha256::digest(&files["hashes.json"]).into();
    assert_eq!(signed_digest, Some(digest));
    let opened = SourcePcp::parse(files).unwrap();
    assert_eq!(opened.version().as_str(), orb_pcp::PCP_VERSION);
    assert_eq!(opened.info().device_public_key.as_deref(), Some("device"));
    let inputs = opened.pipeline_inputs();
    assert_eq!(inputs.left_ir_png, b"synthetic-left-png");
    assert_eq!(inputs.right_ir_png, b"synthetic-right-png");
    assert_eq!(inputs.thumbnail_png, b"synthetic-face-png");
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
        i["left_ir_multiframe_image_ids"] = json!([FRAME_A, FRAME_B])
    });
    files.insert(format!("iris/{FRAME_A}.png"), vec![9]);
    files.insert(format!("iris/{FRAME_B}.png"), vec![8]);
    let mut bio = pipeline();
    bio.extra_normalized.insert(FRAME_A.into(), frame(5));
    let source = SourcePcp::parse(files).unwrap();
    let ctx = context();
    with_build_request(
        &source,
        &bio,
        &ctx,
        OutputKeys::generate().recipients(),
        |request| {
            let orb_pcp::BiometricPolicy::Included { images, .. } = &request.biometrics else {
                panic!("must include")
            };
            let [first, second] = images.left.multiframe else {
                panic!("two frames")
            };
            assert_eq!(first.normalized.as_ref().unwrap().image, &[5; 16]);
            assert!(second.normalized.is_none());
        },
    )
    .unwrap();
    let new = build_and_open(&source, &bio, &ctx);
    verify_completed_pcp(&source, &bio, &ctx, &new.files).unwrap();
    assert_eq!(
        new.files[&format!("normalized_iris/{FRAME_A}_normalized_image.bin")],
        [5; 16]
    );

    // Normalization for an image ID the source does not reference.
    let mut bio = pipeline();
    bio.extra_normalized.insert(FRAME_B.into(), frame(5));
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
fn source_shares_without_a_sharing_version_are_carried_as_they_are() {
    let mut files = source_files("2.1");
    for index in 0..3 {
        files.insert(
            format!("iris_code_shares_{index}.json"),
            iris_code_share(index, false),
        );
    }
    let source = SourcePcp::parse(files.clone()).unwrap();
    let (bio, ctx) = (pipeline(), context());
    let new = build_and_open(&source, &bio, &ctx);
    verify_completed_pcp(&source, &bio, &ctx, &new.files).unwrap();
    assert_eq!(new.files["iris_codes.json"], IRIS_CODES);
    assert_eq!(
        new.files["iris_code_shares_1.json"],
        files["iris_code_shares_1.json"]
    );
}
