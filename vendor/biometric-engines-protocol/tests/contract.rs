use biometric_engines_protocol::{
    PROTOCOL_VERSION, Request, Response,
    face::{invalid_request_reason::Reason, *},
    failure::Kind,
    protobuf,
    request::Operation,
    response::Outcome,
};
use prost::Message;

fn request_roundtrip(operation: Operation) {
    let request = Request::new(u64::MAX, operation);
    assert_eq!(
        protobuf::decode_request(&protobuf::encode_request(&request)).unwrap(),
        request
    );
}

fn response_roundtrip(outcome: Outcome) {
    let response = Response::new(u64::MAX, outcome);
    assert_eq!(
        protobuf::decode_response(&protobuf::encode_response(&response)).unwrap(),
        response
    );
}

#[test]
fn generated_messages_roundtrip_all_products_sources_and_frames() {
    let image_sources = [
        face_image::Source::Orb(vec![1]),
        face_image::Source::VanillaSelfie(vec![2]),
        face_image::Source::LightGuard(LightGuard {
            illuminated: vec![3],
            unilluminated: vec![4],
            matching_frame: LightGuardMatchingFrame::Illuminated as i32,
        }),
        face_image::Source::LightGuard(LightGuard {
            illuminated: vec![3],
            unilluminated: vec![4],
            matching_frame: LightGuardMatchingFrame::Unilluminated as i32,
        }),
        face_image::Source::Rtms(vec![5]),
    ];

    // Test roundtrips of DeepFace and GrayBadge requests
    for credential_img in &image_sources {
        for challenge_img in &image_sources {
            for live_img in &image_sources {
                request_roundtrip(Operation::DeepFace(DeepFaceRequest {
                    credential: Some(FaceImage {
                        source: Some(credential_img.clone()),
                    }),
                    live: Some(FaceImage {
                        source: Some(live_img.clone()),
                    }),
                    challenge: Some(FaceImage {
                        source: Some(challenge_img.clone()),
                    }),
                }));
                request_roundtrip(Operation::GrayBadge(GrayBadgeRequest {
                    live: Some(FaceImage {
                        source: Some(live_img.clone()),
                    }),
                    challenge: Some(FaceImage {
                        source: Some(challenge_img.clone()),
                    }),
                }));
            }
        }
    }

    // Test roundtrips of Embedding request
    for img in &image_sources {
        request_roundtrip(Operation::Embedding(EmbeddingRequest {
            image: Some(FaceImage {
                source: Some(img.clone()),
            }),
        }));
    }
}

#[test]
fn incomplete_requests_are_preserved_for_worker_validation() {
    for request in [
        Request::default(),
        Request {
            protocol_version: 99,
            request_id: 42,
            operation: None,
        },
        Request::new(42, Operation::DeepFace(DeepFaceRequest::default())),
        Request::new(42, Operation::Embedding(EmbeddingRequest { image: None })),
    ] {
        assert_eq!(
            protobuf::decode_request(&protobuf::encode_request(&request)).unwrap(),
            request
        );
    }

    let mut bytes = protobuf::encode_request(&Request {
        protocol_version: 1,
        request_id: 42,
        operation: None,
    });
    bytes.extend_from_slice(&[0xa2, 0x06, 0]); // Unknown operation field 100.
    assert!(
        protobuf::decode_request(&bytes)
            .unwrap()
            .operation
            .is_none()
    );

    let mut bytes = DeepFaceRequest::default().encode_to_vec();
    bytes.extend_from_slice(&[0x0a, 0]);
    assert_eq!(
        DeepFaceRequest::decode(bytes.as_slice())
            .unwrap()
            .credential
            .unwrap()
            .source,
        None
    );

    let bytes = [0x0a, 2, 0x0a, 0];
    assert_eq!(
        DeepFaceRequest::decode(bytes.as_slice())
            .unwrap()
            .credential
            .unwrap()
            .source,
        Some(face_image::Source::Orb(vec![]))
    );
}

#[test]
fn malformed_and_oversized_messages_are_bounded() {
    for bytes in [
        vec![0xff],
        vec![0x1a, 1, 0xff],
        vec![0; biometric_engines_protocol::framing::MAX_FRAME_BYTES + 1],
    ] {
        let rejected = protobuf::decode_request(&bytes).unwrap_err();
        assert_eq!(rejected.request_id, 0);
        assert!(protobuf::decode_response(&bytes).is_err());
    }
}

#[allow(clippy::too_many_lines)]
#[test]
fn image_byte_limits_are_enforced_per_image_and_per_request() {
    let image = |source| {
        Some(FaceImage {
            source: Some(source),
        })
    };
    let light_guard = |illuminated: usize, unilluminated: usize| {
        face_image::Source::LightGuard(LightGuard {
            illuminated: vec![1; illuminated],
            unilluminated: vec![1; unilluminated],
            matching_frame: LightGuardMatchingFrame::Illuminated as i32,
        })
    };
    let deep_face = |credential, live, challenge| {
        Operation::DeepFace(DeepFaceRequest {
            credential: image(credential),
            live: image(live),
            challenge: image(challenge),
        })
    };
    let decode = |operation| {
        protobuf::decode_request(&protobuf::encode_request(&Request::new(7, operation)))
    };
    let small = || face_image::Source::Rtms(vec![1]);
    let over = MAX_IMAGE_BYTES + 1;

    for operation in [
        deep_face(
            face_image::Source::Orb(vec![1; MAX_IMAGE_BYTES]),
            light_guard(MAX_IMAGE_BYTES, MAX_IMAGE_BYTES),
            small(),
        ),
        Operation::Embedding(EmbeddingRequest {
            image: image(face_image::Source::VanillaSelfie(vec![1; MAX_IMAGE_BYTES])),
        }),
    ] {
        decode(operation).unwrap();
    }

    for (operation, role) in [
        (
            deep_face(face_image::Source::Orb(vec![1; over]), small(), small()),
            ImageRole::Credential,
        ),
        (
            deep_face(small(), light_guard(over, 1), small()),
            ImageRole::Live,
        ),
        (
            deep_face(small(), light_guard(1, over), small()),
            ImageRole::Live,
        ),
        (
            deep_face(small(), small(), face_image::Source::Rtms(vec![1; over])),
            ImageRole::Challenge,
        ),
        (
            Operation::GrayBadge(GrayBadgeRequest {
                live: image(face_image::Source::VanillaSelfie(vec![1; over])),
                challenge: image(small()),
            }),
            ImageRole::Live,
        ),
        (
            Operation::GrayBadge(GrayBadgeRequest {
                live: image(small()),
                challenge: image(face_image::Source::Rtms(vec![1; over])),
            }),
            ImageRole::Challenge,
        ),
        (
            Operation::Embedding(EmbeddingRequest {
                image: image(face_image::Source::Orb(vec![1; over])),
            }),
            ImageRole::EmbeddingInput,
        ),
    ] {
        let rejected = decode(operation).unwrap_err();
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

    let quarter = MAX_TOTAL_IMAGE_BYTES / 4;
    decode(deep_face(
        face_image::Source::Orb(vec![1; quarter]),
        light_guard(quarter, quarter),
        face_image::Source::Rtms(vec![1; quarter]),
    ))
    .unwrap();
    let rejected = decode(deep_face(
        face_image::Source::Orb(vec![1; quarter]),
        light_guard(quarter, quarter),
        face_image::Source::Rtms(vec![1; quarter + 1]),
    ))
    .unwrap_err();
    assert_eq!(rejected.request_id, 7);
    assert_eq!(
        rejected.failure,
        Failure::invalid(Reason::TotalImagesTooLarge(ByteLimitExceeded {
            limit_bytes: MAX_TOTAL_IMAGE_BYTES as u64,
        }))
        .into()
    );

    // Requests of other versions are left for the worker to reject as unsupported.
    let request = Request {
        protocol_version: PROTOCOL_VERSION + 1,
        request_id: 7,
        operation: Some(Operation::Embedding(EmbeddingRequest {
            image: image(face_image::Source::Orb(vec![1; over])),
        })),
    };
    assert_eq!(
        protobuf::decode_request(&protobuf::encode_request(&request)).unwrap(),
        request
    );
}

#[test]
fn response_scores_require_presence_and_finite_values_but_accept_zero() {
    response_roundtrip(Outcome::DeepFace(DeepFaceResult {
        similarity_credential_live: Some(0.0),
        similarity_credential_challenge: Some(-0.2),
        similarity_live_challenge: Some(0.7),
        debug_report: Some("debug".into()),
    }));
    response_roundtrip(Outcome::GrayBadge(GrayBadgeResult {
        similarity_live_challenge: Some(0.0),
        debug_report: Some("debug".into()),
    }));
    for bad in [
        None,
        Some(f64::NAN),
        Some(f64::INFINITY),
        Some(f64::NEG_INFINITY),
    ] {
        for index in 0..3 {
            let mut scores = [Some(0.0); 3];
            scores[index] = bad;
            let result = DeepFaceResult {
                similarity_credential_live: scores[0],
                similarity_credential_challenge: scores[1],
                similarity_live_challenge: scores[2],
                debug_report: Some("debug".into()),
            };
            assert!(
                protobuf::decode_response(&protobuf::encode_response(&Response::new(
                    1,
                    Outcome::DeepFace(result)
                )))
                .is_err()
            );
        }
        assert!(
            protobuf::decode_response(&protobuf::encode_response(&Response::new(
                1,
                Outcome::GrayBadge(GrayBadgeResult {
                    similarity_live_challenge: bad,
                    debug_report: Some("debug".into()),
                })
            )))
            .is_err()
        );
    }
    for response in [
        Response {
            protocol_version: PROTOCOL_VERSION,
            request_id: 1,
            outcome: None,
        },
        Response {
            protocol_version: 99,
            request_id: 1,
            outcome: None,
        },
        Response::new(
            1,
            Outcome::Failure(biometric_engines_protocol::Failure::default()),
        ),
        Response::new(
            1,
            Outcome::Failure(biometric_engines_protocol::Failure {
                kind: Some(Kind::Protocol(
                    biometric_engines_protocol::ProtocolFailure::default(),
                )),
            }),
        ),
    ] {
        assert!(protobuf::decode_response(&protobuf::encode_response(&response)).is_err());
    }
}

#[test]
fn failures_roundtrip_every_reason_target_and_location() {
    for code in [
        FailureCode::InvalidImage,
        FailureCode::TemplateFailed,
        FailureCode::MatchingFailed,
        FailureCode::Internal,
    ] {
        for failure in [
            Failure::new(code),
            Failure::new(code).at_image(ImageRole::Credential),
            Failure::new(code).at_comparison(ComparisonRole::CredentialLive),
            Failure::new(code).at_comparison(ComparisonRole::CredentialChallenge),
            Failure::new(code).at_comparison(ComparisonRole::LiveChallenge),
        ] {
            response_roundtrip(Outcome::Failure(failure.into()));
        }
    }
    for reason in [
        Reason::MissingImage(EmptyReason {}),
        Reason::MissingSource(EmptyReason {}),
        Reason::InvalidMatchingFrame(EmptyReason {}),
        Reason::EmptyImage(EmptyReason {}),
        Reason::ImageTooLarge(ByteLimitExceeded {
            limit_bytes: MAX_IMAGE_BYTES as u64,
        }),
        Reason::TotalImagesTooLarge(ByteLimitExceeded {
            limit_bytes: MAX_TOTAL_IMAGE_BYTES as u64,
        }),
    ] {
        response_roundtrip(Outcome::Failure(
            Failure::invalid(reason)
                .at_image(ImageRole::EmbeddingInput)
                .into(),
        ));
    }
    for value in 1..=41 {
        let reason = ValidationReason::try_from(value).unwrap();
        for target in [
            ValidationTarget::Image,
            ValidationTarget::IlluminatedFrame,
            ValidationTarget::UnilluminatedFrame,
            ValidationTarget::LightGuardPair,
        ] {
            for role in [
                ImageRole::Credential,
                ImageRole::Live,
                ImageRole::Challenge,
                ImageRole::EmbeddingInput,
            ] {
                response_roundtrip(Outcome::Failure(
                    Failure::validation(reason, target).at_image(role).into(),
                ));
            }
        }
    }
    for reason in [
        biometric_engines_protocol::protocol_failure::Reason::MalformedMessage(
            biometric_engines_protocol::EmptyReason {},
        ),
        biometric_engines_protocol::protocol_failure::Reason::UnsupportedVersion(
            biometric_engines_protocol::EmptyReason {},
        ),
        biometric_engines_protocol::protocol_failure::Reason::InvalidOperation(
            biometric_engines_protocol::EmptyReason {},
        ),
        biometric_engines_protocol::protocol_failure::Reason::MessageTooLarge(
            biometric_engines_protocol::ByteLimitExceeded { limit_bytes: 64 },
        ),
    ] {
        response_roundtrip(Outcome::Failure(reason.into()));
    }
}

#[test]
fn malformed_failure_details_remain_rejected_without_conversion() {
    let valid = Failure::validation(ValidationReason::NoFaceDetected, ValidationTarget::Image)
        .at_image(ImageRole::Live);
    let mut failures = vec![
        Failure::default(),
        Failure {
            code: 999,
            ..Default::default()
        },
        Failure::new(FailureCode::InvalidRequest),
        Failure::new(FailureCode::ValidationFailed),
        Failure::invalid(Reason::MissingImage(EmptyReason {})).at_image(ImageRole::Unspecified),
        Failure {
            invalid_request_reason: Some(InvalidRequestReason::default()),
            ..Failure::new(FailureCode::InvalidRequest)
        },
        Failure {
            invalid_request_reason: Some(InvalidRequestReason::default()),
            ..Failure::new(FailureCode::Internal)
        },
        Failure {
            location: None,
            ..valid.clone()
        },
        valid.clone().at_comparison(ComparisonRole::CredentialLive),
        Failure {
            location: Some(failure::Location::Image(99)),
            ..valid.clone()
        },
    ];
    for (reason, target) in [(0, 1), (99, 1), (1, 0), (1, 99)] {
        failures.push(Failure {
            validation_failure: Some(ValidationFailure { reason, target }),
            ..valid.clone()
        });
    }
    for failure in failures {
        assert!(
            protobuf::decode_response(&protobuf::encode_response(&Response::new(
                1,
                Outcome::Failure(failure.into())
            )))
            .is_err()
        );
    }
}

#[test]
fn embedding_metadata_and_encoded_length_bound_are_preserved() {
    let embedding = EmbeddingResult {
        vector: "x".repeat(MAX_ENCODED_EMBEDDING_BYTES),
        r#type: "face".into(),
        version: "1".into(),
        inference_backend: "onnx".into(),
        debug_report: Some("debug".into()),
    };
    response_roundtrip(Outcome::Embedding(embedding.clone()));
    let response = Response::new(
        1,
        Outcome::Embedding(EmbeddingResult {
            vector: "x".repeat(MAX_ENCODED_EMBEDDING_BYTES + 1),
            ..embedding
        }),
    );
    assert!(protobuf::decode_response(&protobuf::encode_response(&response)).is_err());
}

#[test]
fn generated_debug_never_exposes_image_or_embedding_contents() {
    let bytes = b"sensitive-payload".to_vec();
    let numeric = format!("{bytes:?}");

    let sources = [
        FaceImage {
            source: Some(face_image::Source::Orb(bytes.clone())),
        },
        FaceImage {
            source: Some(face_image::Source::VanillaSelfie(bytes.clone())),
        },
        FaceImage {
            source: Some(face_image::Source::LightGuard(LightGuard {
                illuminated: bytes.clone(),
                unilluminated: bytes.clone(),
                matching_frame: 1,
            })),
        },
        FaceImage {
            source: Some(face_image::Source::Rtms(bytes.clone())),
        },
    ];
    for source in sources {
        let debug = format!("{source:?}");
        assert!(!debug.contains(&numeric));

        let request = Request::new(
            1,
            Operation::Embedding(EmbeddingRequest {
                image: Some(source.clone()),
            }),
        );
        assert!(!format!("{request:?}").contains(&numeric));

        let request = Request::new(
            1,
            Operation::DeepFace(DeepFaceRequest {
                credential: Some(source.clone()),
                live: Some(source.clone()),
                challenge: Some(source.clone()),
            }),
        );
        assert!(!format!("{request:?}").contains(&numeric));

        let request = Request::new(
            1,
            Operation::GrayBadge(GrayBadgeRequest {
                live: Some(source.clone()),
                challenge: Some(source),
            }),
        );
        assert!(!format!("{request:?}").contains(&numeric));
    }

    let response = Response::new(
        1,
        Outcome::Embedding(EmbeddingResult {
            vector: "sensitive-vector".into(),
            ..Default::default()
        }),
    );
    assert!(!format!("{response:?}").contains("sensitive-vector"));

    let failure = Failure {
        debug_report: Some("sensitive-report".into()),
        ..Failure::validation(ValidationReason::SpoofDetected, ValidationTarget::Image)
            .at_image(ImageRole::Live)
    };
    let debug = format!("{failure:?}");
    assert!(debug.contains("ValidationFailed") && debug.contains("Image(Live)"));
    let envelope = biometric_engines_protocol::Failure::from(failure);
    for output in [
        debug,
        envelope.to_string(),
        format!("{:?}", Response::new(1, Outcome::Failure(envelope))),
    ] {
        assert!(!output.contains("sensitive-report"));
    }
}
