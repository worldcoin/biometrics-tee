//! Invented per-version profiles for mapping coverage, not captured packages.

use crate::support::{FRAME_A, iris_code_share, source_files};
use di_migration_pcp::Files;
use serde_json::{Value, json};

pub fn version_profile(version: &str, optional: bool) -> Files {
    let mut files = source_files(version);
    let face = if version == "0.3" {
        json!([
            {"embedding":"old-face-a", "head_pose":{"yaw":1,"pitch":2}},
            {"embedding":"old-face-b", "head_pose":{"yaw":3,"pitch":4}}
        ])
    } else {
        json!([{"embedding":"old-face", "embedding_version":"old-model"}])
    };
    files.insert(
        "face_embeddings.json".into(),
        serde_json::to_vec(&face).unwrap(),
    );
    let mut info: Value = serde_json::from_slice(&files["info.json"]).unwrap();
    let info = info.as_object_mut().unwrap();
    info.remove("id_commitment");
    info.remove("left_iris_code_aggregate_image_ids");
    if version.starts_with("0.") {
        info.remove("thumbnail_image_id");
    } else {
        info.insert("qr_code".into(), json!("synthetic-qr"));
        info.insert(
            "orb_public_key_certificate".into(),
            json!("synthetic-certificate"),
        );
    }
    if ("2.1"..="2.8").contains(&version) {
        info.insert("orb_country".into(), json!("TEST"));
        info.insert("software_version".into(), Value::Null);
    }
    if ("2.3"..="2.8").contains(&version) {
        info.insert("software_version".into(), json!("old-orb-software"));
    }
    if ("2.4"..="2.8").contains(&version) {
        info.insert("id_commitment".into(), json!("old-commitment"));
    }
    if version == "0.2" {
        files.remove("face/thumbnail.png");
        files.remove("face_embeddings.json");
    }
    for index in 0..3 {
        let name = format!("iris_code_shares_{index}.json");
        // 2.0 packages may lack shares; 2.0 and 2.1 shares have no sharing version.
        if version == "2.0" && !optional {
            files.remove(&name);
        } else {
            let with_version = !matches!(version, "2.0" | "2.1");
            files.insert(name, iris_code_share(index, with_version));
        }
    }
    if optional && ("2.5"..="2.8").contains(&version) {
        files.insert(
            "face_ir_and_thermal/face_ir.png".into(),
            b"synthetic-face-ir".to_vec(),
        );
        files.insert(
            "face_ir_and_thermal/thermal.png".into(),
            b"synthetic-thermal".to_vec(),
        );
    }
    if ("2.6"..="2.8").contains(&version) {
        info.insert("left_ir_multiframe_image_ids".into(), json!([FRAME_A]));
        info.insert("right_ir_multiframe_image_ids".into(), json!([]));
        info.insert(
            "left_iris_code_aggregate_image_ids".into(),
            json!(["left-id", FRAME_A]),
        );
        files.insert(
            format!("iris/{FRAME_A}.png"),
            b"synthetic-extra-frame".to_vec(),
        );
        files.insert(
            format!("normalized_iris/{FRAME_A}_normalized_image.bin"),
            b"old-extra-normalization".to_vec(),
        );
    }
    if matches!(version, "2.7" | "2.8") {
        files.insert("di_iris_embeddings.pb".into(), b"old-di-sentinel".to_vec());
        for index in 0..3 {
            files.insert(format!("di_iris_embeddings_shares_{index}.pb"), vec![99]);
        }
    }
    if version == "2.8" {
        info.insert("device_public_key".into(), json!("old-device"));
        info.insert("device_public_key_salt".into(), json!("old-device-salt"));
    }
    files.insert(
        "normalized_iris/left_normalized_image.bin".into(),
        b"old-normalization".to_vec(),
    );
    files.insert("info.json".into(), serde_json::to_vec(info).unwrap());
    // Present in real sources; its contents are never read.
    files.insert(
        "backend_keys.json".into(),
        b"synthetic-backend-keys".to_vec(),
    );
    files
}
