//! Pins the envelope field numbers shared with upstream `biometric-engines-protocol`.
use di_worker_protocol::{
    EmptyReason, Failure, Request, Response,
    migration::{self, MigrationRequest},
    protobuf,
    protocol_failure::Reason,
    request::Operation,
    response::Outcome,
};

#[test]
fn migration_request_uses_operation_field_6() {
    let request = Request::new(
        1,
        Operation::Migration(MigrationRequest {
            face: vec![9],
            left_iris: Vec::new(),
            right_iris: Vec::new(),
        }),
    );
    // protocol_version = 1, request_id = 1, operation 6: { face (1) = [9] }
    assert_eq!(
        protobuf::encode_request(&request),
        [0x08, 1, 0x10, 1, 0x32, 3, 0x0a, 1, 9]
    );
}

#[test]
fn migration_failures_use_outcome_3_and_kind_3() {
    let failure = migration::Failure::new(migration::FailureCode::Internal);
    let response = Response::new(1, Outcome::Failure(failure.into()));
    // outcome 3: { kind 3: { code (1) = INTERNAL (5) } }
    assert_eq!(
        protobuf::encode_response(&response),
        [0x08, 1, 0x10, 1, 0x1a, 4, 0x1a, 2, 0x08, 5]
    );
}

#[test]
fn protocol_failures_use_kind_1() {
    let failure = Failure::from(Reason::InvalidOperation(EmptyReason {}));
    let response = Response::new(1, Outcome::Failure(failure));
    // outcome 3: { kind 1: { invalid_operation (4) = {} } }
    assert_eq!(
        protobuf::encode_response(&response),
        [0x08, 1, 0x10, 1, 0x1a, 4, 0x0a, 2, 0x22, 0]
    );
}

#[test]
fn migration_results_use_outcome_7() {
    // outcome 7 with an empty result; decode_response rejects it, so check the raw encoding.
    let response = Response::new(1, Outcome::Migration(Box::default()));
    assert_eq!(
        protobuf::encode_response(&response),
        [0x08, 1, 0x10, 1, 0x3a, 0]
    );
}

#[test]
fn upstream_face_outcomes_are_skipped_as_unknown_fields() {
    // An upstream `Response` with outcome 6 (face embedding), as the full worker schema encodes it.
    let bytes = [0x08, 1, 0x10, 1, 0x32, 3, 0x0a, 1, b'x'];
    let error = protobuf::decode_response(&bytes).unwrap_err();
    assert_eq!(error, Reason::MalformedMessage(EmptyReason {}).into());
}
