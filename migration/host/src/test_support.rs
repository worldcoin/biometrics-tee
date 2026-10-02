//! Fakes shared by the route tests.

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use bytes::Bytes;
use di_migration_enclave_types::KeyAttestation;
use di_migration_storage::StorageError;

use crate::{
    AppState,
    enclave::{EnclaveClient, Error},
    store::{BlobStore, StoreError},
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

/// Answers every readiness check; the job paths are unused until the worker lands.
pub struct HealthyStore;

#[async_trait]
impl BlobStore for HealthyStore {
    async fn check_ready(&self) -> Result<(), StoreError> {
        Ok(())
    }

    async fn get_pcp(&self, _: &str) -> Result<Bytes, StoreError> {
        unimplemented!("not exercised by these tests")
    }

    async fn put_result(&self, _: &str, _: Vec<u8>) -> Result<String, StoreError> {
        unimplemented!("not exercised by these tests")
    }
}

/// Fails every readiness check.
pub struct FailingStore;

fn unreachable() -> StoreError {
    StoreError::Bucket(StorageError::Failed {
        operation: "test",
        detail: "unreachable".to_owned(),
    })
}

#[async_trait]
impl BlobStore for FailingStore {
    async fn check_ready(&self) -> Result<(), StoreError> {
        Err(unreachable())
    }

    async fn get_pcp(&self, _: &str) -> Result<Bytes, StoreError> {
        Err(unreachable())
    }

    async fn put_result(&self, _: &str, _: Vec<u8>) -> Result<String, StoreError> {
        Err(unreachable())
    }
}

/// Builds state around `client` with healthy storage and a fixed host IP.
pub fn state_with(client: Arc<dyn EnclaveClient>) -> AppState {
    AppState::new(
        client,
        Arc::new(HealthyStore),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
    )
}
