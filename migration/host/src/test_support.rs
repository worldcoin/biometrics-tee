//! Fakes shared by the unit tests.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    num::NonZeroUsize,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use bytes::Bytes;
use di_migration_enclave_types::{KeyAttestation, MigrateRequest, MigrateResponse};
use di_migration_storage::{Reason, StorageError};
use tokio::sync::Notify;

use crate::{
    AppState,
    enclave::{EnclaveClient, Error},
    queue::{Job, JobQueue},
    readiness::Readiness,
    store::{BlobStore, JobStore, StoreError},
};

/// Answers with a fixed key and document, and echoes migrations.
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

    async fn migrate(&self, request: MigrateRequest) -> Result<MigrateResponse, Error> {
        Ok(MigrateResponse {
            blob: request.blob.to_vec(),
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

    async fn migrate(&self, _: MigrateRequest) -> Result<MigrateResponse, Error> {
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

    async fn migrate(&self, request: MigrateRequest) -> Result<MigrateResponse, Error> {
        StubEnclave::default().migrate(request).await
    }
}

/// Holds each migration until released, so a test can observe one in flight.
///
/// Both handles use `notify_one`: neither side is guaranteed to be waiting yet, and only
/// `notify_one` stores a permit for a wake that arrives first.
pub struct GatedEnclave {
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

impl GatedEnclave {
    /// The fake, a handle that fires once a migration reached it, and one that lets it finish.
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

    async fn encryption_key(&self) -> Result<KeyAttestation, Error> {
        StubEnclave::default().encryption_key().await
    }

    async fn migrate(&self, request: MigrateRequest) -> Result<MigrateResponse, Error> {
        self.entered.notify_one();
        self.release.notified().await;
        StubEnclave::default().migrate(request).await
    }
}

/// A job's recorded outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Migrated(String),
    Failed(Reason),
}

#[derive(Default)]
struct Memory {
    pcps: HashMap<String, Vec<u8>>,
    results: HashMap<String, Vec<u8>>,
    outcomes: HashMap<String, Outcome>,
    last_error: Option<StoreError>,
}

/// S3 and the job table in memory, with switches for the failures the worker must handle.
#[derive(Default)]
pub struct MemoryStore {
    memory: Mutex<Memory>,
    failing_writes: bool,
    resolved_elsewhere: bool,
}

fn unreachable() -> StoreError {
    StorageError::Failed {
        operation: "test",
        detail: "unreachable".to_owned(),
    }
}

impl MemoryStore {
    /// A store holding a sealed PCP for `job_id`.
    pub fn with_pcp(job_id: &str, pcp: &[u8]) -> Self {
        Self::default().and_pcp(job_id, pcp)
    }

    /// Adds a sealed PCP for `job_id`.
    pub fn and_pcp(self, job_id: &str, pcp: &[u8]) -> Self {
        self.lock()
            .pcps
            .insert(format!("pcp/{job_id}"), pcp.to_vec());
        self
    }

    /// Fails every result write.
    pub const fn failing_writes(mut self) -> Self {
        self.failing_writes = true;
        self
    }

    /// Every row is already resolved, as if it timed out first.
    pub const fn resolved_elsewhere(mut self) -> Self {
        self.resolved_elsewhere = true;
        self
    }

    pub fn result(&self, job_id: &str) -> Option<Vec<u8>> {
        self.lock().results.get(job_id).cloned()
    }

    pub fn outcome(&self, job_id: &str) -> Option<Outcome> {
        self.lock().outcomes.get(job_id).cloned()
    }

    pub fn last_error(&self) -> Option<StoreError> {
        self.lock().last_error.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Memory> {
        self.memory.lock().expect("lock should hold")
    }

    fn record(&self, job_id: &str, outcome: Outcome) -> Result<(), StoreError> {
        if self.resolved_elsewhere {
            self.lock().last_error = Some(StoreError::NotMigrating);
            return Err(StoreError::NotMigrating);
        }
        self.lock().outcomes.insert(job_id.to_owned(), outcome);
        Ok(())
    }
}

#[async_trait]
impl BlobStore for MemoryStore {
    async fn check_ready(&self) -> Result<(), StoreError> {
        Ok(())
    }

    async fn get_pcp(&self, object_key: &str) -> Result<Bytes, StoreError> {
        self.lock()
            .pcps
            .get(object_key)
            .map(|pcp| Bytes::from(pcp.clone()))
            .ok_or_else(unreachable)
    }

    async fn put_result(&self, job_id: &str, blob: Vec<u8>) -> Result<String, StoreError> {
        if self.failing_writes {
            return Err(unreachable());
        }
        self.lock().results.insert(job_id.to_owned(), blob);
        Ok(format!("result/{job_id}"))
    }
}

#[async_trait]
impl JobStore for MemoryStore {
    async fn check_ready(&self) -> Result<(), StoreError> {
        Ok(())
    }

    async fn mark_migrated(&self, job_id: &str, result_key: &str) -> Result<(), StoreError> {
        self.record(job_id, Outcome::Migrated(result_key.to_owned()))
    }

    async fn mark_failed(&self, job_id: &str, reason: Reason) -> Result<(), StoreError> {
        self.record(job_id, Outcome::Failed(reason))
    }
}

/// Fails every call.
pub struct FailingStore;

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

#[async_trait]
impl JobStore for FailingStore {
    async fn check_ready(&self) -> Result<(), StoreError> {
        Err(unreachable())
    }

    async fn mark_migrated(&self, _: &str, _: &str) -> Result<(), StoreError> {
        Err(unreachable())
    }

    async fn mark_failed(&self, _: &str, _: Reason) -> Result<(), StoreError> {
        Err(unreachable())
    }
}

/// A job for `id` with the object key the API would send.
pub fn job(id: &str) -> Job {
    Job {
        job_id: id.to_owned(),
        object_key: format!("pcp/{id}"),
        sub: "sub".to_owned(),
        device_public_key: "device-key".to_owned(),
    }
}

/// Builds state around `client` with healthy storage, a 16-job queue and a fixed host IP.
pub fn state_with(client: Arc<dyn EnclaveClient>) -> AppState {
    state_with_capacity(client, 16)
}

/// As [`state_with`], with a queue capped at `capacity`.
pub fn state_with_capacity(client: Arc<dyn EnclaveClient>, capacity: usize) -> AppState {
    let store = Arc::new(MemoryStore::default());
    AppState::new(
        Arc::clone(&client),
        Arc::new(Readiness::new(client, store.clone(), store)),
        Arc::new(JobQueue::new(
            NonZeroUsize::new(capacity).expect("capacity should be non-zero"),
        )),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
    )
}
