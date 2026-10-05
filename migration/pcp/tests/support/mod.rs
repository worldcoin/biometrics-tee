//! In-memory synthetic fixtures. Images and biometric values are invented
//! placeholders for mapping checks; builder keys are generated during tests.

use di_migration_pcp::*;
use serde_json::json;

pub fn source_files(version: &str) -> Files {
    let timestamp = if version.starts_with("0.") {
        json!(1700000000)
    } else {
        json!("1700000000")
    };
    let info = json!({
        "signup_id": "synthetic-orb-signup", "signup_id_salt": "old-salt",
        "timestamp": timestamp, "timestamp_salt": "capture-salt",
        "orb_id": "original-orb", "operator_id": "original-operator",
        "left_ir_image_id": "left-id", "right_ir_image_id": "right-id",
        "thumbnail_image_id": "face-id", "id_commitment": "original-commitment",
        "left_iris_code_aggregate_image_ids": ["old-aggregate"]
    });
    [
        (
            "hashes.json",
            serde_json::to_vec(&json!({"version": version})).unwrap(),
        ),
        ("hashes.sign", b"synthetic-signature".to_vec()),
        ("info.json", serde_json::to_vec(&info).unwrap()),
        ("iris/left_ir.png", b"synthetic-left-png".to_vec()),
        ("iris/right_ir.png", b"synthetic-right-png".to_vec()),
        ("face/thumbnail.png", b"synthetic-face-png".to_vec()),
        (
            "iris_codes.json",
            b"{ \"IRIS_version\": \"old\", \"left_iris_code\": null }\n".to_vec(),
        ),
        (
            "face_embeddings.json",
            b"[{\"head_pose\":{\"yaw\":1}}]".to_vec(),
        ),
    ]
    .into_iter()
    .map(|(p, b)| (p.to_owned(), b))
    .collect()
}

pub fn context() -> MigrationContext {
    MigrationContext {
        tee_version: "0.1.0-test".into(),
        migrated_ts: 1800000000,
    }
}

// Fixed, invented values for mapping and encoding checks; no inference runs.
pub fn pipeline() -> PreparedBiometrics<'static> {
    let iris_eye = || orb_pcp::DaugmanEyeData {
        iris_code: Some("new-code"),
        mask_code: Some("new-mask"),
        iris_code_shares: ["code-0", "code-1", "code-2"],
        mask_code_shares: ["mask-0", "mask-1", "mask-2"],
    };
    let di_eye = || orb_pcp::DiEyeData {
        embedding: &[1, 2],
        mirror_embedding: &[3, 4],
        embedding_f32: &[0.1, 0.2],
        mirror_embedding_f32: &[0.3, 0.4],
        embedding_shares: [&[11, 12], &[21, 22], &[31, 32]],
        mirror_embedding_shares: [&[13, 14], &[23, 24], &[33, 34]],
    };
    let normalized = || orb_pcp::NormalizedIrisFrame {
        image: &[1; 16],
        mask: &[2; 16],
        image_resized: &[3; 8],
        mask_resized: &[4; 8],
    };
    PreparedBiometrics {
        metadata: PipelineMetadata {
            biometric_pipeline_version: "pipeline-1".into(),
            di_model_version: "1.2.3".into(),
            iris_version: "iris-1".into(),
            di_inference_backend: "test-runtime".into(),
            duration_ms: Some(1),
        },
        face_embeddings: vec![orb_pcp::FaceEmbedding {
            embedding: "new-face",
            embedding_type: "test-face",
            embedding_version: "face-2",
            embedding_inference_backend: "test-runtime",
        }],
        daugman: orb_pcp::DaugmanData {
            iris_version: Some("iris-1"),
            shares_version: "test-iris-shares",
            left: iris_eye(),
            right: iris_eye(),
        },
        di: orb_pcp::DiData {
            model_version: "1.2.3",
            inference_backend: "test-runtime",
            embedding_version: "test-di-encoding",
            shares_version: "test-di-shares",
            left: Some(di_eye()),
            right: Some(di_eye()),
        },
        left_normalized: normalized(),
        right_normalized: normalized(),
        extra_normalized: Default::default(),
    }
}
