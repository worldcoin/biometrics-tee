use std::{net::IpAddr, sync::Arc};

use crate::{
    enclave::EnclaveClient,
    readiness::Readiness,
    store::{BlobStore, JobStore},
};

/// Dependencies shared by API request handlers.
#[derive(Clone)]
pub struct AppState {
    enclave_client: Arc<dyn EnclaveClient>,
    readiness: Arc<Readiness>,
    host_ip: IpAddr,
}

impl AppState {
    /// Creates API state from the enclave client, storage and this pod's IP.
    #[must_use]
    pub fn new(
        enclave_client: Arc<dyn EnclaveClient>,
        blob_store: Arc<dyn BlobStore>,
        job_store: Arc<dyn JobStore>,
        host_ip: IpAddr,
    ) -> Self {
        Self {
            readiness: Arc::new(Readiness::new(
                Arc::clone(&enclave_client),
                blob_store,
                job_store,
            )),
            enclave_client,
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

    /// This pod's IP, reported with the attestation.
    #[must_use]
    pub const fn host_ip(&self) -> IpAddr {
        self.host_ip
    }
}
