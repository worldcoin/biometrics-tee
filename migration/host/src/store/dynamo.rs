use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use di_migration_primitives::{Reason, host_api::JobRequest};
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

    async fn mark_migrated(&self, job: &JobRequest, result_key: &str) -> Result<(), StoreError> {
        self.table
            .mark_migrated(&job.job_id, &job.sub, result_key, unix_now())
            .await
    }

    async fn mark_failed(&self, job: &JobRequest, reason: Reason) -> Result<(), StoreError> {
        self.table
            .mark_failed(&job.job_id, &job.sub, reason, unix_now())
            .await
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}
