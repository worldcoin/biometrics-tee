//! Storage the host reads jobs from and writes results to, behind traits so the worker and
//! readiness can be tested without AWS.

mod dynamo;
mod s3;

use async_trait::async_trait;
use bytes::Bytes;
use di_migration_storage::Reason;
pub use di_migration_storage::StorageError as StoreError;

pub use dynamo::DynamoJobStore;
pub use s3::S3BlobStore;

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

/// The job rows the host finishes.
#[async_trait]
pub trait JobStore: Send + Sync {
    /// Checks the table is reachable.
    async fn check_ready(&self) -> Result<(), StoreError>;

    /// Marks a `migrating` job `migrated`.
    async fn mark_migrated(&self, job_id: &str, result_key: &str) -> Result<(), StoreError>;

    /// Marks a `migrating` job `failed`.
    async fn mark_failed(&self, job_id: &str, reason: Reason) -> Result<(), StoreError>;
}
