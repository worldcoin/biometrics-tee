use std::{net::IpAddr, sync::Arc};

use crate::{enclave::EnclaveClient, queue::JobQueue, readiness::Readiness};

/// Dependencies shared by API request handlers.
#[derive(Clone)]
pub struct AppState {
    enclave_client: Arc<dyn EnclaveClient>,
    readiness: Arc<Readiness>,
    queue: Arc<JobQueue>,
    host_ip: IpAddr,
}

impl AppState {
    /// Creates API state; `queue` is the one the worker drains.
    #[must_use]
    pub const fn new(
        enclave_client: Arc<dyn EnclaveClient>,
        readiness: Arc<Readiness>,
        queue: Arc<JobQueue>,
        host_ip: IpAddr,
    ) -> Self {
        Self {
            enclave_client,
            readiness,
            queue,
            host_ip,
        }
    }

    /// Returns a shared enclave client.
    #[must_use]
    pub fn enclave_client(&self) -> Arc<dyn EnclaveClient> {
        Arc::clone(&self.enclave_client)
    }

    /// Cached readiness of the host's dependencies.
    #[must_use]
    pub fn readiness(&self) -> &Readiness {
        &self.readiness
    }

    /// The job queue the worker drains.
    #[must_use]
    pub fn queue(&self) -> &JobQueue {
        &self.queue
    }

    /// This pod's IP, reported with the attestation.
    #[must_use]
    pub const fn host_ip(&self) -> IpAddr {
        self.host_ip
    }
}
