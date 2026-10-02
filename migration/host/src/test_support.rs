//! Fakes shared by the route tests.

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use di_migration_enclave_types::KeyAttestation;

use crate::{
    AppState,
    enclave::{EnclaveClient, Error},
};

/// Answers every call with a fixed key and document.
pub struct StubEnclave {
    pub public_key: Vec<u8>,
}

impl Default for StubEnclave {
    fn default() -> Self {
        Self {
            public_key: vec![9u8; 1216],
        }
    }
}

#[async_trait]
impl EnclaveClient for StubEnclave {
    async fn health(&self) -> Result<(), Error> {
        Ok(())
    }

    async fn encryption_key(&self) -> Result<KeyAttestation, Error> {
        Ok(KeyAttestation {
            document: b"document".to_vec(),
            public_key: self.public_key.clone(),
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

    async fn encryption_key(&self) -> Result<KeyAttestation, Error> {
        Err(self.0.clone())
    }
}

/// Healthy, and counts health checks so caching can be asserted.
#[derive(Default)]
pub struct CountingEnclave {
    health_calls: AtomicUsize,
}

impl CountingEnclave {
    pub fn health_calls(&self) -> usize {
        self.health_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl EnclaveClient for CountingEnclave {
    async fn health(&self) -> Result<(), Error> {
        self.health_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn encryption_key(&self) -> Result<KeyAttestation, Error> {
        StubEnclave::default().encryption_key().await
    }
}

/// Builds state around `client`, with a fixed host IP.
pub fn state_with(client: Arc<dyn EnclaveClient>) -> AppState {
    AppState::new(client, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)))
}
