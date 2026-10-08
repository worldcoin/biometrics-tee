//! The host's internal HTTP API, called only by the Migration API.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::{EnclaveId, JobId, Reason};

/// `GET /attestation`: who the enclave is, how to verify it, and where to dispatch jobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationResponse {
    /// The boot's identity, derived from `enclave_public_key`.
    pub enclave_id: EnclaveId,
    /// COSE attestation document, standard padded base64.
    pub attestation: String,
    /// Full X-Wing public key, standard padded base64.
    pub enclave_public_key: String,
    /// The host pod's IP, which the API stores per job.
    pub host_ip: IpAddr,
}

/// `POST /jobs`: a job the API has committed as `migrating`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRequest {
    /// The job to run.
    pub job_id: JobId,
    /// Where the sealed PCP was uploaded; must be the job's own `pcp/` key.
    pub object_key: String,
    /// Account the ownership proof was verified for.
    pub sub: String,
    /// The app's attested device key as its RFC 7638 canonical JWK.
    pub device_public_key: String,
    /// The boot the PCP was sealed to; a restarted enclave refuses the job.
    pub enclave_id: EnclaveId,
    /// Unix seconds after which the job reads as `timeout`; the host skips it then.
    pub deadline: u64,
}

/// `202` body of `POST /jobs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobAccepted {
    /// Always `queued`, for a new or a repeated dispatch.
    pub status: String,
}

impl JobAccepted {
    /// The job is queued, now or by an earlier dispatch.
    #[must_use]
    pub fn queued() -> Self {
        Self {
            status: "queued".to_owned(),
        }
    }
}

/// `GET /capacity`: what the API's admission poll sums across hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capacity {
    /// Waiting plus running jobs.
    pub queued: usize,
    /// The most the host holds.
    pub capacity: usize,
}

/// The body of every error response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorEnvelope {
    /// Whether resending the same request can succeed.
    pub allow_retry: bool,
    /// What failed.
    pub error: ErrorBody,
}

/// A machine-readable code and a human message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// One of [`codes`].
    pub code: String,
    /// Human-readable; never names internals.
    pub message: String,
}

/// Machine-readable error codes.
pub mod codes {
    use super::Reason;

    /// The enclave did not answer in time.
    pub const ENCLAVE_TIMEOUT: &str = "enclave_timeout";
    /// The enclave could not be reached.
    pub const ENCLAVE_UNREACHABLE: &str = "enclave_unreachable";
    /// An unexpected failure; detail stays in the host's log.
    pub const INTERNAL_ERROR: &str = "internal_error";
    /// The job request was malformed.
    pub const INVALID_JOB: &str = "invalid_job";
    /// The job was sealed to a previous enclave boot.
    pub const ENCLAVE_CHANGED: &str = Reason::EnclaveChanged.as_str();
    /// The host is at its safety cap.
    pub const HOST_BUSY: &str = Reason::HostBusy.as_str();
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Capacity, ErrorBody, ErrorEnvelope, JobAccepted, JobRequest};
    use crate::{EnclaveId, JobId};

    /// Pins the wire shape both services build against.
    #[test]
    fn a_job_request_has_the_agreed_field_names() {
        let request = JobRequest {
            job_id: "3f0c5e2a-8a51-4c47-9d8e-0b9f3c1d2e4a"
                .parse::<JobId>()
                .expect("uuid"),
            object_key: "pcp/3f0c5e2a-8a51-4c47-9d8e-0b9f3c1d2e4a".to_owned(),
            sub: "sub".to_owned(),
            device_public_key: "key".to_owned(),
            enclave_id: EnclaveId::from_commitment([1; 32]),
            deadline: 1_800_000_600,
        };

        assert_eq!(
            serde_json::to_value(&request).expect("json"),
            json!({
                "job_id": "3f0c5e2a-8a51-4c47-9d8e-0b9f3c1d2e4a",
                "object_key": "pcp/3f0c5e2a-8a51-4c47-9d8e-0b9f3c1d2e4a",
                "sub": "sub",
                "device_public_key": "key",
                "enclave_id": "01".repeat(32),
                "deadline": 1_800_000_600,
            })
        );
    }

    #[test]
    fn a_job_request_with_a_bad_id_does_not_parse() {
        let body = json!({
            "job_id": "not-a-uuid",
            "object_key": "pcp/x",
            "sub": "sub",
            "device_public_key": "key",
            "enclave_id": "01".repeat(32),
        });

        assert!(serde_json::from_value::<JobRequest>(body).is_err());
    }

    #[test]
    fn responses_have_the_agreed_field_names() {
        assert_eq!(
            serde_json::to_value(JobAccepted::queued()).expect("json"),
            json!({"status": "queued"})
        );
        assert_eq!(
            serde_json::to_value(Capacity {
                queued: 1,
                capacity: 4
            })
            .expect("json"),
            json!({"queued": 1, "capacity": 4})
        );
        assert_eq!(
            serde_json::to_value(ErrorEnvelope {
                allow_retry: true,
                error: ErrorBody {
                    code: "enclave_timeout".to_owned(),
                    message: "late".to_owned(),
                },
            })
            .expect("json"),
            json!({"allowRetry": true, "error": {"code": "enclave_timeout", "message": "late"}})
        );
    }
}
