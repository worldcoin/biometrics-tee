//! Storage the host reads jobs from and writes results to, behind traits so the worker and
//! readiness can be tested without AWS.

mod s3;

use async_trait::async_trait;
use bytes::Bytes;
use di_migration_storage::StorageError;

pub use s3::S3BlobStore;

/// Failures talking to storage.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The PCP bucket failed.
    #[error(transparent)]
    Bucket(#[from] StorageError),
}

/// Where sealed PCPs come from and migrated results go.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Checks the bucket is reachable.
    async fn check_ready(&self) -> Result<(), StoreError>;

    /// Reads the sealed PCP the app uploaded.
    async fn get_pcp(&self, object_key: &str) -> Result<Bytes, StoreError>;

    /// Writes the migrated PCP once; a result already there is kept. Returns its key.
    async fn put_result(&self, job_id: &str, blob: Vec<u8>) -> Result<String, StoreError>;
}
