//! Fakes shared by the route tests.

use std::sync::Arc;

use async_trait::async_trait;
use di_dev_enclave_primitives::{MigrateRequest, MigrateResponse};
use tokio::sync::Notify;

use crate::{
    AppState,
    enclave::{EnclaveClient, Error},
};

/// Echoes the PCP straight back.
pub struct EchoEnclave;

#[async_trait]
impl EnclaveClient for EchoEnclave {
    async fn health(&self) -> Result<(), Error> {
        Ok(())
    }

    async fn migrate(&self, request: MigrateRequest) -> Result<MigrateResponse, Error> {
        Ok(MigrateResponse {
            pcp: request.pcp.to_vec(),
        })
    }
}

/// Fails every call with a fixed error.
pub struct FailingEnclave(pub Error);

#[async_trait]
impl EnclaveClient for FailingEnclave {
    async fn health(&self) -> Result<(), Error> {
        Err(self.0.clone())
    }

    async fn migrate(&self, _: MigrateRequest) -> Result<MigrateResponse, Error> {
        Err(self.0.clone())
    }
}

/// Holds a migration inside the enclave until released, so a test can have one in flight.
///
/// Both handles use `notify_one`, not `notify_waiters`: neither side is guaranteed to be
/// waiting yet, and only `notify_one` stores a permit for a wake that arrives first.
pub struct GatedEnclave {
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

impl GatedEnclave {
    /// Returns the fake, a handle that fires once a migration has reached the enclave, and the
    /// handle that lets it finish.
    pub fn new() -> (Self, Arc<Notify>, Arc<Notify>) {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        (
            Self {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            },
            entered,
            release,
        )
    }
}

#[async_trait]
impl EnclaveClient for GatedEnclave {
    async fn health(&self) -> Result<(), Error> {
        Ok(())
    }

    async fn migrate(&self, request: MigrateRequest) -> Result<MigrateResponse, Error> {
        self.entered.notify_one();
        self.release.notified().await;
        Ok(MigrateResponse {
            pcp: request.pcp.to_vec(),
        })
    }
}

/// Builds state around `client`.
pub fn state_with(client: Arc<dyn EnclaveClient>) -> AppState {
    AppState::new(client)
}
