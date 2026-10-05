//! Invented per-version profiles for mapping coverage, not captured packages.

use super::source_files;
use di_migration_pcp::Files;
use serde_json::{Value, json};

pub fn legacy_profile(version: &str, optional: bool) -> Files {
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
    if version != "2.0" || optional {
        for index in 0..3 {
            files.insert(
                format!("iris_code_shares_{index}.json"),
                serde_json::to_vec(&json!({"IRIS_shares_version":"old", "recipient":index}))
                    .unwrap(),
            );
        }
    }
    let mut backend =
        json!({"iris":{"public_key":"historical"},"normalized_iris":{"public_key":"historical"}});
    if version != "0.2" {
        backend["face"] = json!({"public_key":"historical"});
    }
    if ("2.5"..="2.8").contains(&version) {
        backend["tier2"] = json!({"encrypted_private_key":"historical-envelope"});
        if optional {
            files.insert(
                "face_ir_and_thermal/face_ir.png".into(),
                b"synthetic-face-ir".to_vec(),
            );
            files.insert(
                "face_ir_and_thermal/thermal.png".into(),
                b"synthetic-thermal".to_vec(),
            );
        }
    }
    if ("2.6"..="2.8").contains(&version) {
        info.insert("left_ir_multiframe_image_ids".into(), json!(["extra-left"]));
        info.insert("right_ir_multiframe_image_ids".into(), json!([]));
        info.insert(
            "left_iris_code_aggregate_image_ids".into(),
            json!(["left-id", "extra-left"]),
        );
        files.insert(
            "iris/extra-left.png".into(),
            b"synthetic-extra-frame".to_vec(),
        );
        files.insert(
            "normalized_iris/extra-left_normalized_image.bin".into(),
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
    files.insert(
        "backend_keys.json".into(),
        serde_json::to_vec(&backend).unwrap(),
    );
    files
}
