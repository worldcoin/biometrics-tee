//! Storage the host reads jobs from and writes results to, behind traits so the job runner and
//! readiness can be tested without AWS.

mod dynamo;
mod s3;

use async_trait::async_trait;
use bytes::Bytes;
use di_migration_primitives::{JobId, Reason, host_api::JobRequest};
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
    async fn put_result(&self, job_id: &JobId, blob: Vec<u8>) -> Result<String, StoreError>;
}

/// The job rows the host finishes.
#[async_trait]
pub trait JobStore: Send + Sync {
    /// Checks the table is reachable.
    async fn check_ready(&self) -> Result<(), StoreError>;

    /// Marks a `migrating` job `migrated` and frees its `sub`, unless it is past its deadline.
    async fn mark_migrated(&self, job: &JobRequest, result_key: &str) -> Result<(), StoreError>;

    /// Marks a `migrating` job `failed` and frees its `sub`, unless it is past its deadline.
    async fn mark_failed(&self, job: &JobRequest, reason: Reason) -> Result<(), StoreError>;
}
