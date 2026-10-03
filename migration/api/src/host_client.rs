//! Typed calls to a host's internal API.

use std::{net::SocketAddr, time::Duration};

use di_migration_primitives::host_api::{
    AttestationResponse, Capacity, ErrorEnvelope, JobRequest, codes as host_api_codes,
};
use reqwest::StatusCode;

/// A capacity poll; short, so one slow host does not delay the whole refresh.
const CAPACITY_TIMEOUT: Duration = Duration::from_secs(1);

/// The host asks its enclave for the key on these calls; its own enclave deadline is 2 s.
const ENCLAVE_BACKED_TIMEOUT: Duration = Duration::from_secs(3);

/// A failed call to a host.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostError {
    /// The host did not answer within the deadline.
    #[error("host timed out")]
    Timeout,
    /// The connection failed.
    #[error("host unreachable: {0}")]
    Unreachable(String),
    /// The host answered with an unexpected status or body.
    #[error("host answered {status}: {code}")]
    Rejected {
        /// The HTTP status.
        status: u16,
        /// The error code from its envelope, or empty.
        code: String,
    },
}

/// Why a host did not queue a job.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "migrate dispatches jobs in a follow-up")
)]
pub enum DispatchError {
    /// The enclave restarted; the PCP was sealed to a key that no longer exists.
    #[error("enclave changed")]
    EnclaveChanged,
    /// The host is over its safety cap.
    #[error("host busy")]
    HostBusy,
    /// Any other failure, including an unreachable host.
    #[error(transparent)]
    Host(#[from] HostError),
}

/// Calls hosts by address; one connection pool for the whole fleet.
#[derive(Debug, Clone)]
pub struct HostClient {
    http: reqwest::Client,
}

impl HostClient {
    /// Builds the shared client.
    ///
    /// # Errors
    ///
    /// The TLS backend failed to initialize.
    pub fn new() -> Result<Self, reqwest::Error> {
        Ok(Self {
            http: reqwest::Client::builder()
                .connect_timeout(CAPACITY_TIMEOUT)
                .build()?,
        })
    }

    /// The host's waiting plus running jobs and its cap.
    pub async fn capacity(&self, host: SocketAddr) -> Result<Capacity, HostError> {
        self.get(host, "/capacity", CAPACITY_TIMEOUT).await
    }

    /// The host's enclave identity, attestation and IP.
    #[cfg_attr(not(test), expect(dead_code, reason = "init uses it in a follow-up"))]
    pub async fn attestation(&self, host: SocketAddr) -> Result<AttestationResponse, HostError> {
        self.get(host, "/attestation", ENCLAVE_BACKED_TIMEOUT).await
    }

    /// Queues `job` on the host; a repeated dispatch is accepted once.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "migrate dispatches jobs in a follow-up")
    )]
    pub async fn submit(&self, host: SocketAddr, job: &JobRequest) -> Result<(), DispatchError> {
        let response = self
            .http
            .post(format!("http://{host}/jobs"))
            .json(job)
            .timeout(ENCLAVE_BACKED_TIMEOUT)
            .send()
            .await
            .map_err(transport)?;
        if response.status() == StatusCode::ACCEPTED {
            return Ok(());
        }

        let error = rejected(response).await;
        match &error {
            HostError::Rejected { code, .. } if code == host_api_codes::ENCLAVE_CHANGED => {
                Err(DispatchError::EnclaveChanged)
            }
            HostError::Rejected { code, .. } if code == host_api_codes::HOST_BUSY => {
                Err(DispatchError::HostBusy)
            }
            _ => Err(error.into()),
        }
    }

    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        host: SocketAddr,
        path: &str,
        timeout: Duration,
    ) -> Result<T, HostError> {
        let response = self
            .http
            .get(format!("http://{host}{path}"))
            .timeout(timeout)
            .send()
            .await
            .map_err(transport)?;
        if response.status() != StatusCode::OK {
            return Err(rejected(response).await);
        }
        response.json().await.map_err(|error| HostError::Rejected {
            status: StatusCode::OK.as_u16(),
            code: format!("undecodable body: {error}"),
        })
    }
}

fn transport(error: reqwest::Error) -> HostError {
    if error.is_timeout() {
        HostError::Timeout
    } else {
        HostError::Unreachable(error.to_string())
    }
}

/// Reads the host's error envelope, if it sent one.
async fn rejected(response: reqwest::Response) -> HostError {
    let status = response.status().as_u16();
    let code = response
        .json::<ErrorEnvelope>()
        .await
        .map(|envelope| envelope.error.code)
        .unwrap_or_default();
    HostError::Rejected { status, code }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use axum::{
        Json, Router,
        http::StatusCode,
        routing::{get, post},
    };
    use di_migration_primitives::{
        EnclaveId, JobId,
        host_api::{AttestationResponse, ErrorBody, ErrorEnvelope, JobRequest},
    };

    use super::{DispatchError, HostClient, HostError};

    async fn serve(router: Router) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("should bind");
        let addr = listener.local_addr().expect("address");
        tokio::spawn(async move { axum::serve(listener, router).await });
        addr
    }

    /// A host whose `/jobs` answers `status` with error `code`.
    async fn host_answering(status: StatusCode, code: &'static str) -> SocketAddr {
        serve(Router::new().route(
            "/jobs",
            post(move || async move {
                (
                    status,
                    Json(ErrorEnvelope {
                        allow_retry: false,
                        error: ErrorBody {
                            code: code.to_owned(),
                            message: String::new(),
                        },
                    }),
                )
            }),
        ))
        .await
    }

    fn job() -> JobRequest {
        let job_id = JobId::new();
        JobRequest {
            object_key: di_migration_storage::schema::pcp_key(&job_id),
            job_id,
            sub: "sub".to_owned(),
            device_public_key: "device-key".to_owned(),
            enclave_id: EnclaveId::from_commitment([1; 32]),
        }
    }

    fn client() -> HostClient {
        HostClient::new().expect("client")
    }

    #[tokio::test]
    async fn an_accepted_job_is_queued() {
        let host =
            serve(Router::new().route("/jobs", post(|| async { StatusCode::ACCEPTED }))).await;

        assert_eq!(client().submit(host, &job()).await, Ok(()));
    }

    /// Pins the host answers migrate turns into a `reason`.
    #[tokio::test]
    async fn host_refusals_map_to_dispatch_errors() {
        let cases = [
            (
                StatusCode::CONFLICT,
                "enclave_changed",
                DispatchError::EnclaveChanged,
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "host_busy",
                DispatchError::HostBusy,
            ),
            (
                StatusCode::GATEWAY_TIMEOUT,
                "enclave_timeout",
                DispatchError::Host(HostError::Rejected {
                    status: 504,
                    code: "enclave_timeout".to_owned(),
                }),
            ),
        ];

        for (status, code, expected) in cases {
            let host = host_answering(status, code).await;

            assert_eq!(client().submit(host, &job()).await, Err(expected), "{code}");
        }
    }

    #[tokio::test]
    async fn an_unreachable_host_is_a_host_error() {
        let host: SocketAddr = "127.0.0.1:9".parse().expect("addr");

        assert!(matches!(
            client().submit(host, &job()).await,
            Err(DispatchError::Host(HostError::Unreachable(_)))
        ));
    }

    #[tokio::test]
    async fn the_attestation_is_decoded() {
        let attestation = AttestationResponse {
            enclave_id: EnclaveId::from_commitment([2; 32]),
            attestation: "ZG9j".to_owned(),
            enclave_public_key: "a2V5".to_owned(),
            host_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
        };
        let served = attestation.clone();
        let host = serve(Router::new().route(
            "/attestation",
            get(move || {
                let served = served.clone();
                async move { Json(served) }
            }),
        ))
        .await;

        assert_eq!(client().attestation(host).await, Ok(attestation));
    }
}
