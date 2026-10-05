use biometric_engines_protocol::{Failure, face, protobuf};
use std::error::Error;

#[test]
fn failure_and_decode_errors_work_with_standard_rust_error_handling() {
    fn decode() -> Result<(), Box<dyn Error + Send + Sync>> {
        protobuf::decode_request(&[0xff])?;
        Ok(())
    }

    fn assert_error<T: Error + Send + Sync + 'static>() {}

    assert_error::<Failure>();
    assert_error::<face::Failure>();
    assert_error::<protobuf::RejectedRequest>();

    let error = decode().unwrap_err();
    let rejected = error.downcast_ref::<protobuf::RejectedRequest>().unwrap();

    assert_eq!(rejected.request_id, 0);
    assert_eq!(
        rejected.source().unwrap().downcast_ref::<Failure>(),
        Some(&rejected.failure)
    );
}
