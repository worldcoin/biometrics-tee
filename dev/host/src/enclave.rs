//! Client boundary between the host and enclave.

use std::time::Duration;

use async_trait::async_trait;
use di_dev_enclave_primitives::{
    self as enclave_primitives, HealthRequest, MigrateRequest, MigrateResponse,
};
use pontifex::{Request, client::ConnectionDetails};
use tokio::time::timeout;

/// Readiness probes must not hang behind a wedged enclave.
const CONTROL_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Bounds how long the single slot can be held; sized for the pipeline, not the echo.
const MIGRATE_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// Failures while calling an enclave operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The Pontifex connection or wire operation failed.
    Transport(String),
    /// The enclave returned a structured operation error.
    Operation(enclave_primitives::Error),
    /// The enclave did not answer within the request deadline.
    Timeout,
}

/// Operations the host requires from the enclave.
#[async_trait]
pub trait EnclaveClient: Send + Sync {
    /// Checks whether the enclave process is reachable and ready.
    async fn health(&self) -> Result<(), Error>;

    /// Migrates one PCP inside the enclave.
    async fn migrate(&self, request: MigrateRequest) -> Result<MigrateResponse, Error>;
}

/// Pontifex-backed enclave client.
#[derive(Debug, Clone, Copy)]
pub struct PontifexEnclaveClient {
    connection: ConnectionDetails,
}

impl PontifexEnclaveClient {
    /// Creates a client for the provided enclave CID and Pontifex port.
    #[must_use]
    pub const fn new(cid: u32, port: u32) -> Self {
        Self {
            connection: ConnectionDetails::new(cid, port),
        }
    }

    /// Sends `request` under `deadline`, flattening the timeout, transport and operation layers.
    async fn call<R, T>(&self, request: R, deadline: Duration) -> Result<T, Error>
    where
        R: Request<Response = Result<T, enclave_primitives::Error>> + Sync,
    {
        timeout(deadline, pontifex::client::send(self.connection, &request))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|error| Error::Transport(error.to_string()))?
            .map_err(Error::Operation)
    }
}

#[async_trait]
impl EnclaveClient for PontifexEnclaveClient {
    async fn health(&self) -> Result<(), Error> {
        self.call(HealthRequest, CONTROL_REQUEST_TIMEOUT).await
    }

    async fn migrate(&self, request: MigrateRequest) -> Result<MigrateResponse, Error> {
        self.call(request, MIGRATE_REQUEST_TIMEOUT).await
    }
}
