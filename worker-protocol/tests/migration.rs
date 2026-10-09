use di_worker_protocol::{
    PROTOCOL_VERSION, Request, Response,
    migration::{invalid_request_reason::Reason, *},
    protobuf,
    request::Operation,
    response::Outcome,
};

fn request(face: usize, left: usize, right: usize) -> Request {
    Request::new(
        7,
        Operation::Migration(MigrationRequest {
            face: vec![1; face],
            left_iris: vec![2; left],
            right_iris: vec![3; right],
        }),
    )
}

fn face_embedding() -> FaceEmbedding {
    FaceEmbedding {
        vector: "face-vector".into(),
        r#type: "face".into(),
        version: "2.0.0".into(),
        inference_backend: "face-engine".into(),
    }
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
        face_embedding: Some(face_embedding()),
        left_iris: Some(left),
        right_iris: Some(eye()),
        iris_code_version: "v2.1".into(),
        iris_model_version: "deep-identifier-1.0.0".into(),
        iris_embedding_version: "1".into(),
        iris_inference_backend: "iris-engine".into(),
    }
}

fn decode(outcome: Outcome) -> Result<Response, di_worker_protocol::Failure> {
    protobuf::decode_response(&protobuf::encode_response(&Response::new(1, outcome)))
}

#[test]
fn requests_roundtrip_and_enforce_the_per_image_limit() {
    for request in [
        request(MAX_IMAGE_BYTES, MAX_IMAGE_BYTES, MAX_IMAGE_BYTES),
        Request::new(7, Operation::Migration(MigrationRequest::default())),
    ] {
        assert_eq!(
            protobuf::decode_request(&protobuf::encode_request(&request)).unwrap(),
            request
        );
    }

    let over = MAX_IMAGE_BYTES + 1;
    for (request, role) in [
        (request(over, 1, 1), ImageRole::Face),
        (request(1, over, 1), ImageRole::LeftIris),
        (request(1, 1, over), ImageRole::RightIris),
    ] {
        let rejected = protobuf::decode_request(&protobuf::encode_request(&request)).unwrap_err();
        assert_eq!(rejected.request_id, 7);
        assert_eq!(
            rejected.failure,
            Failure::invalid(Reason::ImageTooLarge(ByteLimitExceeded {
                limit_bytes: MAX_IMAGE_BYTES as u64,
            }))
            .at_image(role)
            .into()
        );
    }

    // Requests of other versions are left for the worker to reject as unsupported.
    let request = Request {
        protocol_version: PROTOCOL_VERSION + 1,
        ..request(over, 1, 1)
    };
    assert_eq!(
        protobuf::decode_request(&protobuf::encode_request(&request)).unwrap(),
        request
    );
}

#[test]
fn results_require_every_part_with_exact_shapes() {
    let valid = Outcome::Migration(Box::new(result(eye())));
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
        assert!(decode(Outcome::Migration(Box::new(result(eye)))).is_err());
    }

    let incomplete = [
        MigrationResult {
            right_iris: None,
            ..result(eye())
        },
        MigrationResult {
            face_embedding: None,
            ..result(eye())
        },
        MigrationResult {
            face_embedding: Some(FaceEmbedding {
                vector: String::new(),
                ..face_embedding()
            }),
            ..result(eye())
        },
        MigrationResult {
            face_embedding: Some(FaceEmbedding {
                vector: "x".repeat(MAX_ENCODED_FACE_EMBEDDING_BYTES + 1),
                ..face_embedding()
            }),
            ..result(eye())
        },
    ];
    for result in incomplete {
        assert!(decode(Outcome::Migration(Box::new(result))).is_err());
    }
}

#[test]
fn failures_require_a_known_code_an_image_and_matching_reason() {
    let mut valid = vec![Failure::new(FailureCode::Internal)];
    for role in [ImageRole::Face, ImageRole::LeftIris, ImageRole::RightIris] {
        for code in [
            FailureCode::InvalidImage,
            FailureCode::QualityRejected,
            FailureCode::SpoofDetected,
            FailureCode::Internal,
        ] {
            valid.push(Failure::new(code).at_image(role));
        }
        for reason in [
            Reason::MissingImage(EmptyReason {}),
            Reason::ImageTooLarge(ByteLimitExceeded {
                limit_bytes: MAX_IMAGE_BYTES as u64,
            }),
        ] {
            valid.push(Failure::invalid(reason).at_image(role));
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
        .at_image(ImageRole::Face),
        Failure::new(FailureCode::QualityRejected),
        Failure {
            image: 99,
            ..Failure::new(FailureCode::SpoofDetected)
        },
        Failure::new(FailureCode::InvalidRequest).at_image(ImageRole::LeftIris),
        Failure {
            invalid_request_reason: Some(InvalidRequestReason::default()),
            ..Failure::new(FailureCode::InvalidRequest).at_image(ImageRole::LeftIris)
        },
        Failure {
            invalid_request_reason: Some(InvalidRequestReason {
                reason: Some(Reason::MissingImage(EmptyReason {})),
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
    let request = request(3, 3, 3);
    let debug = format!("{request:?}");
    for bytes in ["[1, 1, 1]", "[2, 2, 2]", "[3, 3, 3]"] {
        assert!(!debug.contains(bytes), "{bytes}");
    }

    let eye = EyeResult {
        iris_code: "sensitive-code".into(),
        ..eye()
    };
    let response = Response::new(1, Outcome::Migration(Box::new(result(eye))));
    let debug = format!("{response:?}");
    assert!(debug.contains("deep-identifier-1.0.0"));
    for secret in ["sensitive-code", "BBBB", "248, 248", "0.5", "face-vector"] {
        assert!(!debug.contains(secret), "{secret}");
    }

    let debug = format!(
        "{:?}",
        Failure::new(FailureCode::SpoofDetected).at_image(ImageRole::Face)
    );
    assert!(debug.contains("SpoofDetected") && debug.contains("Face"));
}
