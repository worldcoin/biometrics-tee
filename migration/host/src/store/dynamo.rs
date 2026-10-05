use async_trait::async_trait;
use di_migration_primitives::{JobId, Reason};
use di_migration_storage::JobTable;

use super::{JobStore, StoreError};

/// The job table behind the [`JobStore`] trait.
#[derive(Debug, Clone)]
pub struct DynamoJobStore {
    table: JobTable,
}

impl DynamoJobStore {
    /// Finishes jobs in `table`.
    #[must_use]
    pub const fn new(table: JobTable) -> Self {
        Self { table }
    }
}

#[async_trait]
impl JobStore for DynamoJobStore {
    async fn check_ready(&self) -> Result<(), StoreError> {
        self.table.check_ready().await
    }

    async fn mark_migrated(&self, job_id: &JobId, result_key: &str) -> Result<(), StoreError> {
        self.table.mark_migrated(job_id, result_key).await
    }

    async fn mark_failed(&self, job_id: &JobId, reason: Reason) -> Result<(), StoreError> {
        self.table.mark_failed(job_id, reason).await
    }
}
