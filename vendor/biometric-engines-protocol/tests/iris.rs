use biometric_engines_protocol::{
    PROTOCOL_VERSION, Request, Response,
    iris::{invalid_request_reason::Reason, *},
    protobuf,
    request::Operation,
    response::Outcome,
};

fn request(left: usize, right: usize) -> Request {
    Request::new(
        7,
        Operation::IrisMigration(MigrationRequest {
            left: Some(IrImage { png: vec![1; left] }),
            right: Some(IrImage {
                png: vec![2; right],
            }),
        }),
    )
}

fn eye() -> EyeResult {
    EyeResult {
        iris_code: "A".repeat(ENCODED_CODE_LEN),
        mask_code: "B".repeat(ENCODED_CODE_LEN),
        embedding: vec![(-8i8).cast_unsigned(); EMBEDDING_SIZE],
        mirror_embedding: vec![7; EMBEDDING_SIZE],
        embedding_f32: vec![0.5; EMBEDDING_SIZE],
        mirror_embedding_f32: vec![-0.5; EMBEDDING_SIZE],
    }
}

fn result(left: EyeResult) -> MigrationResult {
    MigrationResult {
        left: Some(left),
        right: Some(eye()),
        iris_code_version: "v2.1".into(),
        model_version: "deep-identifier-1.0.0".into(),
        embedding_version: "1".into(),
        inference_backend: "tract".into(),
    }
}

fn decode(outcome: Outcome) -> Result<Response, biometric_engines_protocol::Failure> {
    protobuf::decode_response(&protobuf::encode_response(&Response::new(1, outcome)))
}

#[test]
fn requests_roundtrip_and_enforce_the_per_image_limit() {
    for request in [
        request(MAX_IMAGE_BYTES, MAX_IMAGE_BYTES),
        Request::new(7, Operation::IrisMigration(MigrationRequest::default())),
    ] {
        assert_eq!(
            protobuf::decode_request(&protobuf::encode_request(&request)).unwrap(),
            request
        );
    }

    for (request, eye) in [
        (request(MAX_IMAGE_BYTES + 1, 1), EyeSide::Left),
        (request(1, MAX_IMAGE_BYTES + 1), EyeSide::Right),
    ] {
        let rejected = protobuf::decode_request(&protobuf::encode_request(&request)).unwrap_err();
        assert_eq!(rejected.request_id, 7);
        assert_eq!(
            rejected.failure,
            Failure::invalid(Reason::ImageTooLarge(ByteLimitExceeded {
                limit_bytes: MAX_IMAGE_BYTES as u64,
            }))
            .at_eye(eye)
            .into()
        );
    }

    // Requests of other versions are left for the worker to reject as unsupported.
    let request = Request {
        protocol_version: PROTOCOL_VERSION + 1,
        ..request(MAX_IMAGE_BYTES + 1, 1)
    };
    assert_eq!(
        protobuf::decode_request(&protobuf::encode_request(&request)).unwrap(),
        request
    );
}

#[test]
fn results_require_both_eyes_with_exact_code_and_embedding_shapes() {
    let valid = Outcome::IrisMigration(Box::new(result(eye())));
    assert_eq!(decode(valid.clone()).unwrap().outcome, Some(valid));

    let invalid_eyes = [
        EyeResult {
            iris_code: "A".repeat(ENCODED_CODE_LEN - 1),
            ..eye()
        },
        EyeResult {
            mask_code: "B".repeat(ENCODED_CODE_LEN + 1),
            ..eye()
        },
        EyeResult {
            embedding: vec![8; EMBEDDING_SIZE],
            ..eye()
        },
        EyeResult {
            mirror_embedding: vec![(-9i8).cast_unsigned(); EMBEDDING_SIZE],
            ..eye()
        },
        EyeResult {
            embedding: vec![0; EMBEDDING_SIZE - 1],
            ..eye()
        },
        EyeResult {
            embedding_f32: vec![0.0; EMBEDDING_SIZE + 1],
            ..eye()
        },
        EyeResult {
            mirror_embedding_f32: vec![f32::NAN; EMBEDDING_SIZE],
            ..eye()
        },
        EyeResult {
            embedding_f32: vec![f32::INFINITY; EMBEDDING_SIZE],
            ..eye()
        },
    ];
    for eye in invalid_eyes {
        assert!(decode(Outcome::IrisMigration(Box::new(result(eye)))).is_err());
    }
    let missing_eye = MigrationResult {
        right: None,
        ..result(eye())
    };
    assert!(decode(Outcome::IrisMigration(Box::new(missing_eye))).is_err());
}

#[test]
fn failures_require_a_known_code_an_eye_and_matching_reason() {
    let mut valid = vec![Failure::new(FailureCode::Internal)];
    for eye in [EyeSide::Left, EyeSide::Right] {
        for code in [
            FailureCode::InvalidImage,
            FailureCode::QualityRejected,
            FailureCode::SpoofDetected,
            FailureCode::Internal,
        ] {
            valid.push(Failure::new(code).at_eye(eye));
        }
        for reason in [
            Reason::MissingImage(EmptyReason {}),
            Reason::EmptyImage(EmptyReason {}),
            Reason::ImageTooLarge(ByteLimitExceeded {
                limit_bytes: MAX_IMAGE_BYTES as u64,
            }),
        ] {
            valid.push(Failure::invalid(reason).at_eye(eye));
        }
    }
    for failure in valid {
        let outcome = Outcome::Failure(failure.into());
        assert_eq!(decode(outcome.clone()).unwrap().outcome, Some(outcome));
    }

    let invalid = [
        Failure::default(),
        Failure {
            code: 99,
            ..Failure::default()
        }
        .at_eye(EyeSide::Left),
        Failure::new(FailureCode::QualityRejected),
        Failure {
            eye: 99,
            ..Failure::new(FailureCode::SpoofDetected)
        },
        Failure::new(FailureCode::InvalidRequest).at_eye(EyeSide::Left),
        Failure {
            invalid_request_reason: Some(InvalidRequestReason::default()),
            ..Failure::new(FailureCode::InvalidRequest).at_eye(EyeSide::Left)
        },
        Failure {
            invalid_request_reason: Some(InvalidRequestReason {
                reason: Some(Reason::EmptyImage(EmptyReason {})),
            }),
            ..Failure::new(FailureCode::Internal)
        },
    ];
    for failure in invalid {
        assert!(decode(Outcome::Failure(failure.into())).is_err());
    }
}

#[test]
fn debug_never_exposes_images_codes_or_embeddings() {
    let request = request(3, 3);
    assert!(!format!("{request:?}").contains("[1, 1, 1]"));

    let eye = EyeResult {
        iris_code: "sensitive-code".into(),
        ..eye()
    };
    let response = Response::new(1, Outcome::IrisMigration(Box::new(result(eye))));
    let debug = format!("{response:?}");
    assert!(debug.contains("deep-identifier-1.0.0"));
    for secret in ["sensitive-code", "BBBB", "248, 248", "0.5"] {
        assert!(!debug.contains(secret), "{secret}");
    }

    let debug = format!(
        "{:?}",
        Failure::new(FailureCode::SpoofDetected).at_eye(EyeSide::Right)
    );
    assert!(debug.contains("SpoofDetected") && debug.contains("Right"));
}
