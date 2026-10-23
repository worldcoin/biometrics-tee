//! Typed adapter over the byte-oriented sandboxed biometric worker.

use di_migration_pcp::PipelineInputs;
use di_worker_protocol::migration::{Failure, MigrationResult};

/// Successful output of one execution of the provisioned biometric pipeline.
pub struct MigrationOutput {
    /// Immutable release identifier of the worker bundle that produced the result.
    pub pipeline_version: String,
    /// Validated biometric pipeline result.
    pub result: MigrationResult,
}

/// The worker launched under Minijail before the async runtime started.
pub trait Worker: Send + Sync {
    /// Runs the complete migration pipeline, returning validated user-level rejection details.
    ///
    /// # Errors
    ///
    /// Returns a validated rejection from the biometric pipeline.
    fn migrate(&self, inputs: PipelineInputs<'_>) -> Result<MigrationOutput, Failure>;

    /// Exits the enclave if the worker died; must not wait for an in-flight request.
    fn check_alive(&self);
}

/// Decodes a worker reply and ensures it belongs to the current migration request.
#[cfg(any(target_os = "linux", test))]
fn decode_result(bytes: &[u8], expected_id: u64) -> Result<Result<MigrationResult, Failure>, ()> {
    use di_worker_protocol::{failure::Kind, response::Outcome};

    let response = di_worker_protocol::protobuf::decode_response(bytes).map_err(|_| ())?;
    if expected_id == 0 || response.request_id != expected_id {
        return Err(());
    }
    match response.outcome.ok_or(())? {
        Outcome::Migration(result) => Ok(Ok(*result)),
        Outcome::Failure(failure) => match failure.kind {
            Some(Kind::Migration(failure)) => Ok(Err(failure)),
            _ => Err(()),
        },
    }
}

#[cfg(target_os = "linux")]
/// Serializes requests to the provisioned sandbox process.
pub struct SandboxWorker {
    worker: std::sync::Mutex<tabernaculum::Worker>,
    next_id: std::sync::atomic::AtomicU64,
    pipeline_version: String,
}

#[cfg(target_os = "linux")]
impl SandboxWorker {
    /// Wraps a started worker with the immutable bundle release identifier.
    #[must_use]
    pub fn new(worker: tabernaculum::Worker, pipeline_version: String) -> Self {
        Self {
            worker: std::sync::Mutex::new(worker),
            next_id: std::sync::atomic::AtomicU64::new(1),
            pipeline_version,
        }
    }
}

#[cfg(target_os = "linux")]
impl Worker for SandboxWorker {
    fn migrate(&self, inputs: PipelineInputs<'_>) -> Result<MigrationOutput, Failure> {
        use di_worker_protocol::{Request, migration::MigrationRequest, request::Operation};
        use std::sync::atomic::Ordering;
        use zeroize::Zeroize;

        let request = MigrationRequest {
            face: inputs.thumbnail_png.to_vec(),
            left_iris: inputs.left_ir_png.to_vec(),
            right_iris: inputs.right_ir_png.to_vec(),
        };
        if let Err(failure) = di_worker_protocol::migration::check_image_limits(&request) {
            return Err(failure);
        }

        let mut worker = self
            .worker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner().fail());
        let id = self.next_id.load(Ordering::Relaxed);
        let next_id = id
            .checked_add(1)
            .filter(|_| id != 0)
            .unwrap_or_else(|| worker.fail());
        self.next_id.store(next_id, Ordering::Relaxed);

        let mut request = Request::new(id, Operation::Migration(request));
        let encoded =
            zeroize::Zeroizing::new(di_worker_protocol::protobuf::encode_request(&request));
        if let Some(Operation::Migration(request)) = request.operation.as_mut() {
            request.face.zeroize();
            request.left_iris.zeroize();
            request.right_iris.zeroize();
        }
        let response = match worker.exchange(&encoded) {
            Ok(response) => zeroize::Zeroizing::new(response),
            Err(tabernaculum::ConnectionError::InvalidRequest) => {
                tracing::warn!(
                    dependency = "worker",
                    bytes = encoded.len(),
                    "worker request rejected before sending"
                );
                return Err(Failure::invalid(
                    di_worker_protocol::migration::invalid_request_reason::Reason::ImageTooLarge(
                        di_worker_protocol::migration::ByteLimitExceeded {
                            limit_bytes: di_worker_protocol::framing::MAX_FRAME_BYTES as u64,
                        },
                    ),
                ));
            }
            Err(_) => worker.fail(),
        };
        let result = decode_result(&response, id).unwrap_or_else(|()| worker.fail())?;
        Ok(MigrationOutput {
            pipeline_version: self.pipeline_version.clone(),
            result,
        })
    }

    fn check_alive(&self) {
        tabernaculum::check_alive_if_idle(&self.worker);
    }
}

#[cfg(test)]
mod tests {
    use di_worker_protocol::{Response, migration, protobuf, response::Outcome};

    use super::decode_result;

    #[test]
    fn worker_response_must_match_request_and_operation() {
        let failure = migration::Failure::new(migration::FailureCode::Internal);
        let response = protobuf::encode_response(&Response::new(
            7,
            di_worker_protocol::Failure::from(failure).into(),
        ));

        assert_eq!(decode_result(&response, 7).unwrap().unwrap_err(), failure);
        assert!(decode_result(&response, 8).is_err());

        let protocol_failure = protobuf::encode_response(&Response::new(
            7,
            Outcome::Failure(
                di_worker_protocol::protocol_failure::Reason::InvalidOperation(
                    di_worker_protocol::EmptyReason {},
                )
                .into(),
            ),
        ));
        assert!(decode_result(&protocol_failure, 7).is_err());
        assert!(decode_result(b"not protobuf", 7).is_err());
    }
}
