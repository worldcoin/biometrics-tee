use std::time::{Duration, SystemTime};

use di_worker_protocol::migration::{ByteLimitExceeded, FailureCode};
use serde_json::{Value, json};

use super::*;
use crate::test_support;

// Synthetic diagnostics: no captured images, templates or real signup data.
const WORKER_REPORT: &str = r#"{
  "worker_version":"test-worker",
  "face":{
    "worker_version":"test-worker",
    "request_type":{"type":"embedding","source":"Orb"},
    "outputs":[{"role":"Face","source":"Orb",
      "captured_image_analyzer":{"version":"test-face","error":null},
      "challenge_response":null,
      "template_generator":{"version":"test-face","extra_diagnostic":{"value":0.1234567890123456789012}}}]
  },
  "iris":{
    "left":{"role":"LeftIris","side":"Left","outputs":{
      "capture_qa":{"metadata":{"irnet_version":"3.5.0"}},"pipeline":{"error":null},"pad":null}},
    "right":{"role":"RightIris","side":"Right","outputs":{
      "capture_qa":{"metadata":{"irnet_version":"3.5.0"}},"pipeline":{"error":null},"pad":null}},
    "pair":{"role":"IrisPair","output":{"gabor":{},"embedding":{},"error":null}}
  }
}"#;

fn report() -> Report {
    let mut report = Report::new(SystemTime::UNIX_EPOCH + Duration::from_millis(123_500));
    report.worker_report(Some(Zeroizing::new(WORKER_REPORT.to_owned())));
    report
}

fn decode(report: &Report, error: Option<Error>) -> Value {
    serde_json::from_str(&report.serialize(&test_support::state(), error).unwrap()).unwrap()
}

#[test]
fn envelope_records_runtime_metadata_and_migration_provenance() {
    let mut state = test_support::state();
    state.set_report_metadata(RuntimeMetadata {
        worker_sha384: Some("ab".repeat(48)),
        hardware: Some(Hardware {
            architecture: "x86_64",
            usable_logical_cpus: Some(2),
            visible_memory_bytes: Some(12 * 1024 * 1024 * 1024),
        }),
        attestation: Some(Measurements {
            measurements_zeroed: false,
            pcrs: (0..=2).map(|i| (i.to_string(), "11".repeat(48))).collect(),
        }),
    });
    let mut report = report();
    report.signup_id = Some("00000000000000000000000100000000".parse().unwrap());
    report.src_signup_id = Some("00000000000000000000000000000000".parse().unwrap());
    report.source_pcp_version = Some("2.7");
    let encoded = report.serialize(&state, None).unwrap();
    assert!(encoded.contains("0.1234567890123456789012"));
    let actual: Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(
        actual["version"],
        hex::encode(Sha256::digest(SCHEMA.as_bytes()))
    );
    assert!(actual["metadata"]["end_timestamp"].as_f64().unwrap() >= 123.5);
    assert_eq!(
        actual["metadata"]["environment"]["boot_id"],
        hex::encode(state.channel().public_key_commitment())
    );
    assert_eq!(actual["signup_id"], json!(report.signup_id));
    assert_eq!(actual["src_signup_id"], json!(report.src_signup_id));
    let metadata = &actual["metadata"];
    assert_eq!(metadata["start_timestamp"], 123.5);
    assert_eq!(metadata["source_pcp_version"], "2.7");
    assert_eq!(
        metadata["software_version"]["main_program_version"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(
        metadata["software_version"]["worker_sha384"],
        "ab".repeat(48)
    );
    assert_eq!(
        metadata["hardware"],
        json!({
            "architecture": "x86_64",
            "usable_logical_cpus": 2,
            "visible_memory_bytes": 12_u64 * 1024 * 1024 * 1024
        })
    );
    assert_eq!(metadata["environment"]["type"], "tee");
    assert_eq!(
        metadata["environment"]["tee"],
        json!({
            "technology": "aws_nitro_enclaves",
            "attestation": {
                "measurements_zeroed": false,
                "pcrs": {"0": "11".repeat(48), "1": "11".repeat(48), "2": "11".repeat(48)}
            }
        })
    );
}

#[test]
fn diagnostics_survive_success_and_failures_after_inference() {
    let original: Value = serde_json::from_str(WORKER_REPORT).unwrap();
    for error in [
        None,
        Some(Error::EmbeddingShareGenerationFailed),
        Some(Error::FailedToBuildPcp),
    ] {
        let mut report = report();
        report.stage = Stage::BuildPcp;
        let value = decode(&report, error);
        assert_eq!(value["iris"], original["iris"]);
        assert_eq!(value["face"]["outputs"], original["face"]["outputs"]);
        assert_eq!(
            value["face"]["request_type"],
            original["face"]["request_type"]
        );
        assert!(value["face"].get("worker_version").is_none());
        assert_eq!(
            value["metadata"]["signup_status"],
            if error.is_some() {
                "Failure"
            } else {
                "Success"
            }
        );
        assert_eq!(
            value["metadata"]["signup_reason"],
            if error.is_some() { "Failure" } else { "Normal" }
        );
        for field in [
            "biometric_summary",
            "pipeline_config",
            "software_constants",
            "migrated_ts",
            "face",
            "iris_engine_metadata_left",
        ] {
            assert!(value["metadata"].get(field).is_none());
        }
        assert!(
            value["metadata"]["software_version"]
                .get("main_program")
                .is_none()
        );
    }
}

#[test]
fn versions_come_from_available_engine_metadata_and_must_agree() {
    let mut source: Value = serde_json::from_str(WORKER_REPORT).unwrap();
    source["iris"]["left"] = Value::Null;
    let mut report = report();
    report.worker_report(Some(Zeroizing::new(source.to_string())));
    assert_eq!(
        decode(&report, None)["metadata"]["software_version"]["iris_engine_version"],
        "3.5.0"
    );
    source["iris"]["left"] =
        json!({"outputs":{"capture_qa":{"metadata":{"irnet_version":"different"}}}});
    report.worker_report(Some(Zeroizing::new(source.to_string())));
    let value = decode(&report, None);
    assert!(
        value["metadata"]["software_version"]
            .get("iris_engine_version")
            .is_none()
    );
    assert_eq!(value["iris"], source["iris"]);
    assert_eq!(
        value["metadata"]["software_version"]["face_engine_version"],
        "test-face"
    );
    assert_eq!(
        value["metadata"]["software_version"]["worker_version"],
        "test-worker"
    );
}

#[test]
fn an_explicit_worker_engine_version_is_available_before_eye_processing() {
    let mut report = Report::new(SystemTime::now());
    report.worker_report(Some(Zeroizing::new(
        r#"{"worker_version":"test-worker","iris_engine_version":"3.6.0","face":null,"iris":null}"#
            .to_owned(),
    )));
    let value = decode(&report, Some(Error::BiometricQualityRejected));
    assert_eq!(
        value["metadata"]["software_version"]["iris_engine_version"],
        "3.6.0"
    );
    assert!(value["iris"].is_null());
}

#[test]
fn partial_worker_failure_keeps_its_image_reason_and_available_diagnostics() {
    let mut report = report();
    report.stage = Stage::Biometrics;
    let failure = Failure::invalid(invalid_request_reason::Reason::ImageTooLarge(
        ByteLimitExceeded { limit_bytes: 1024 },
    ))
    .at_image(ImageRole::RightIris);
    report.worker_failure(&failure);
    let value = decode(&report, Some(Error::BiometricInvalidRequest));
    assert_eq!(
        value["pipeline_errors"]["migration_error"],
        json!({
            "stage":"biometrics", "code":"BiometricInvalidRequest", "image":"RightIris",
            "invalid_request_reason":{"image_too_large":{"limit_bytes":1024}}
        })
    );
    assert!(value["face"].is_object());
    report.worker_failure(&Failure::new(FailureCode::SpoofDetected).at_image(ImageRole::IrisPair));
    let value = decode(&report, Some(Error::BiometricSpoofDetected));
    assert_eq!(value["metadata"]["signup_status"], "Fraud");
    assert_eq!(value["metadata"]["signup_reason"], "Fraud");
    assert_eq!(
        value["pipeline_errors"]["migration_error"]["image"],
        "IrisPair"
    );
    let quality = decode(&report, Some(Error::BiometricQualityRejected));
    assert_eq!(quality["metadata"]["signup_status"], "Failure");
}

#[test]
fn unavailable_and_invalid_worker_reports_preserve_enclave_failure_context() {
    for worker in [
        None,
        Some("not json"),
        Some("[]"),
        Some(r#"{"iris":7}"#),
        Some(r#"{"face":{"request_type":7,"outputs":[]}}"#),
    ] {
        let mut report = Report::new(SystemTime::now());
        report.stage = Stage::PrepareBiometrics;
        report.worker_report(worker.map(|value| Zeroizing::new(value.to_owned())));
        let value = decode(&report, Some(Error::IncompleteBiometricPipelineResult));
        assert!(value["face"].is_null());
        assert!(value["iris"].is_null());
        assert_eq!(value["metadata"]["signup_status"], "Failure");
        assert_eq!(
            value["pipeline_errors"]["migration_error"]["stage"],
            "prepare_biometrics"
        );
        assert!(
            value["metadata"]["software_version"]
                .get("iris_engine_version")
                .is_none()
        );
    }
}

#[test]
fn size_limit_applies_to_the_complete_report_without_truncating_engine_output() {
    let source = format!(
        r#"{{"iris":{{"detail":"{}"}}}}"#,
        "x".repeat(MAX_MIGRATION_DIAGNOSTIC_BYTES - 30)
    );
    assert!(source.len() < MAX_MIGRATION_DIAGNOSTIC_BYTES);
    let mut report = Report::new(SystemTime::now());
    report.worker_report(Some(Zeroizing::new(source)));
    assert!(report.serialize(&test_support::state(), None).is_none());
}

#[test]
fn memory_observations_require_valid_units_and_checked_conversion() {
    assert_eq!(
        memory_bytes("MemTotal:  123 kB\nMemFree: 2 kB\n"),
        Some(123 * 1024)
    );
    for text in [
        "",
        "MemTotal: 0 kB",
        "MemTotal: -1 kB",
        "MemTotal: 123 MB",
        "MemTotal: 123 kB extra",
        "MemTotal: 18446744073709551615 kB",
    ] {
        assert_eq!(memory_bytes(text), None);
    }
    assert_eq!(
        timestamp(SystemTime::UNIX_EPOCH + Duration::from_millis(123_500)),
        Some(123.5)
    );
    assert!(timestamp(SystemTime::UNIX_EPOCH - Duration::from_secs(1)).is_none());
}
