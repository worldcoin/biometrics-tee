use biometric_engines_protocol::{
    face::*, protobuf, request::Operation, response::Outcome, Ready, Request, Response,
    PROTOCOL_VERSION,
};
use prost::Message;

fn embedding() -> EmbeddingResult {
    EmbeddingResult {
        vector: "sensitive-vector".into(),
        r#type: "ghostfacenet".into(),
        version: "1".into(),
        inference_backend: "tract".into(),
        debug_report: None,
    }
}

fn roundtrip(
    outcome: pose_guard_result::Outcome,
) -> Result<Response, biometric_engines_protocol::Failure> {
    protobuf::decode_response(&protobuf::encode_response(&Response::new(
        7,
        Outcome::PoseGuard(PoseGuardResult {
            outcome: Some(outcome),
        }),
    )))
}

#[test]
fn readiness_is_backwards_compatible_and_support_is_explicit() {
    let old_bytes = [0x08, 0x01];
    assert!(protobuf::decode_ready(&old_bytes));
    assert!(!protobuf::ready_supports_poseguard(&old_bytes));
    assert_eq!(protobuf::encode_ready(), old_bytes);
    let ready = protobuf::encode_ready_with_poseguard(true);
    assert!(protobuf::decode_ready(&ready));
    assert!(protobuf::ready_supports_poseguard(&ready));
    for bytes in [
        vec![0xff],
        Ready {
            protocol_version: PROTOCOL_VERSION + 1,
            supports_pose_guard: true,
        }
        .encode_to_vec(),
    ] {
        assert!(!protobuf::ready_supports_poseguard(&bytes));
    }
}

#[test]
fn bounded_requests_roundtrip_without_debug_disclosure() {
    let request = Request::new(
        7,
        Operation::PoseGuard(PoseGuardRequest {
            image: b"sensitive-image".to_vec(),
            target: Some(PoseGuardTarget {
                pitch: 20.0,
                yaw: -35.0,
            }),
            reference: Some(embedding()),
        }),
    );
    assert_eq!(
        protobuf::decode_request(&protobuf::encode_request(&request)).unwrap(),
        request
    );
    let debug = format!("{request:?}");
    assert!(!debug.contains("sensitive"));
    let request = Request::new(
        7,
        Operation::PoseGuard(PoseGuardRequest {
            image: vec![1; MAX_IMAGE_BYTES + 1],
            ..Default::default()
        }),
    );
    assert_eq!(
        protobuf::decode_request(&protobuf::encode_request(&request))
            .unwrap_err()
            .request_id,
        7
    );
}

#[test]
fn results_preserve_finite_scores_identity_and_rejection_semantics() {
    use pose_guard_result::Outcome::*;
    for score in [-1.0, 0.0, 0.4, 1.0] {
        assert!(roundtrip(Similarity(score)).is_ok());
    }
    for score in [f64::NAN, f64::INFINITY, -1.01, 1.01] {
        assert!(roundtrip(Similarity(score)).is_err());
    }
    assert!(roundtrip(Identity(embedding())).is_ok());
    assert!(roundtrip(Identity(EmbeddingResult::default())).is_err());
    assert!(roundtrip(Identity(EmbeddingResult {
        debug_report: Some("private".into()),
        ..embedding()
    }))
    .is_err());
    for reason in [
        ValidationReason::PoseGuardTargetMismatch,
        ValidationReason::NoFaceDetected,
    ] {
        assert!(roundtrip(Rejection(PoseGuardRejection {
            failure: Some(
                Failure::validation(reason, ValidationTarget::Image).at_image(ImageRole::Challenge)
            ),
            retryable: true,
        }))
        .is_ok());
    }
    for failure in [
        Failure::validation(ValidationReason::SpoofDetected, ValidationTarget::Image)
            .at_image(ImageRole::Challenge),
        Failure::validation(
            ValidationReason::LightGuardScoreTooLow,
            ValidationTarget::Image,
        )
        .at_image(ImageRole::Challenge),
        Failure::new(FailureCode::TemplateFailed),
        Failure::new(FailureCode::MatchingFailed),
    ] {
        assert!(roundtrip(Rejection(PoseGuardRejection {
            failure: Some(failure.clone()),
            retryable: false
        }))
        .is_ok());
        assert!(roundtrip(Rejection(PoseGuardRejection {
            failure: Some(failure),
            retryable: true
        }))
        .is_err());
    }
    for failure in [
        None,
        Some(Failure::new(FailureCode::Internal)),
        Some(Failure::default()),
    ] {
        assert!(roundtrip(Rejection(PoseGuardRejection {
            failure,
            retryable: false
        }))
        .is_err());
    }
    let absent = Response::new(7, Outcome::PoseGuard(PoseGuardResult::default()));
    assert!(protobuf::decode_response(&protobuf::encode_response(&absent)).is_err());
}
