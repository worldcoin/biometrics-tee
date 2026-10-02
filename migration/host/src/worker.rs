//! The single worker: one job at a time from fetch to recorded outcome.

use std::sync::Arc;

use di_migration_enclave_types::MigrateRequest;
use di_migration_storage::Reason;

use crate::{
    enclave::{self, EnclaveClient},
    queue::{Job, JobQueue},
    store::{BlobStore, JobStore, StoreError},
};

/// Everything a job touches.
pub struct Worker {
    queue: Arc<JobQueue>,
    enclave_client: Arc<dyn EnclaveClient>,
    blob_store: Arc<dyn BlobStore>,
    job_store: Arc<dyn JobStore>,
}

impl Worker {
    /// Creates a worker draining `queue`.
    #[must_use]
    pub fn new(
        queue: Arc<JobQueue>,
        enclave_client: Arc<dyn EnclaveClient>,
        blob_store: Arc<dyn BlobStore>,
        job_store: Arc<dyn JobStore>,
    ) -> Self {
        Self {
            queue,
            enclave_client,
            blob_store,
            job_store,
        }
    }

    /// Runs jobs until the process stops; the enclave serves one migration at a time.
    pub async fn run(self) {
        loop {
            let job = self.queue.next().await;
            self.handle(&job).await;
            self.queue.finish(&job.job_id);
        }
    }

    /// Runs `job` and records its outcome.
    pub async fn handle(&self, job: &Job) {
        let recorded = match self.migrate(job).await {
            Ok(result_key) => self.job_store.mark_migrated(&job.job_id, &result_key).await,
            Err(reason) => self.job_store.mark_failed(&job.job_id, reason).await,
        };

        match recorded {
            Ok(()) => {}
            Err(StoreError::NotMigrating) => tracing::warn!(
                job_id = %job.job_id,
                "job was resolved elsewhere first, e.g. it timed out; outcome not recorded"
            ),
            // The row stays `migrating` and reads as `timeout` once its deadline passes.
            Err(error) => tracing::error!(
                job_id = %job.job_id,
                %error,
                dependency = "dynamodb",
                "failed to record the job outcome"
            ),
        }
    }

    async fn migrate(&self, job: &Job) -> Result<String, Reason> {
        let blob = self
            .blob_store
            .get_pcp(&job.object_key)
            .await
            .map_err(|error| {
                tracing::error!(job_id = %job.job_id, %error, dependency = "s3", "failed to read the sealed PCP");
                Reason::S3Error
            })?;

        let migrated = self
            .enclave_client
            .migrate(MigrateRequest {
                blob,
                sub: job.sub.clone(),
                device_public_key: job.device_public_key.clone(),
            })
            .await
            .map_err(|error| {
                tracing::error!(job_id = %job.job_id, ?error, dependency = "enclave", "migration failed");
                match error {
                    enclave::Error::Timeout => Reason::Timeout,
                    enclave::Error::Transport(_) | enclave::Error::Operation(_) => {
                        Reason::EnclaveError
                    }
                }
            })?;

        self.blob_store
            .put_result(&job.job_id, migrated.blob)
            .await
            .map_err(|error| {
                tracing::error!(job_id = %job.job_id, %error, dependency = "s3", "failed to write the result");
                Reason::S3Error
            })
    }
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, sync::Arc};

    use di_migration_storage::Reason;

    use super::Worker;
    use crate::{
        enclave,
        queue::{Job, JobQueue},
        store::StoreError,
        test_support::{FailingEnclave, GatedEnclave, MemoryStore, Outcome, StubEnclave, job},
    };

    fn worker(enclave: Arc<dyn enclave::EnclaveClient>, store: &Arc<MemoryStore>) -> Worker {
        Worker::new(
            Arc::new(JobQueue::new(NonZeroUsize::new(4).expect("non-zero"))),
            enclave,
            store.clone(),
            store.clone(),
        )
    }

    #[tokio::test]
    async fn a_migrated_blob_is_stored_and_the_job_marked_migrated() {
        let store = Arc::new(MemoryStore::with_pcp("a", b"sealed"));

        worker(Arc::new(StubEnclave::default()), &store)
            .handle(&job("a"))
            .await;

        assert_eq!(store.result("a").as_deref(), Some(b"sealed".as_slice()));
        assert_eq!(
            store.outcome("a"),
            Some(Outcome::Migrated("result/a".to_owned()))
        );
    }

    /// Pins each failure to the reason the app sees.
    #[tokio::test]
    async fn each_failure_is_recorded_with_its_reason() {
        let cases: [(Arc<dyn enclave::EnclaveClient>, Arc<MemoryStore>, Reason); 4] = [
            (
                Arc::new(StubEnclave::default()),
                Arc::new(MemoryStore::default()),
                Reason::S3Error,
            ),
            (
                Arc::new(FailingEnclave(enclave::Error::Timeout)),
                Arc::new(MemoryStore::with_pcp("a", b"sealed")),
                Reason::Timeout,
            ),
            (
                Arc::new(FailingEnclave(enclave::Error::Transport(
                    "refused".to_owned(),
                ))),
                Arc::new(MemoryStore::with_pcp("a", b"sealed")),
                Reason::EnclaveError,
            ),
            (
                Arc::new(StubEnclave::default()),
                Arc::new(MemoryStore::with_pcp("a", b"sealed").failing_writes()),
                Reason::S3Error,
            ),
        ];

        for (enclave, store, reason) in cases {
            worker(enclave, &store).handle(&job("a")).await;

            assert_eq!(store.outcome("a"), Some(Outcome::Failed(reason)));
        }
    }

    /// A job that timed out first keeps its `failed` row; the late result is not recorded.
    #[tokio::test]
    async fn a_job_resolved_elsewhere_is_not_overwritten() {
        let store = Arc::new(MemoryStore::with_pcp("a", b"sealed").resolved_elsewhere());

        worker(Arc::new(StubEnclave::default()), &store)
            .handle(&job("a"))
            .await;

        assert_eq!(store.outcome("a"), None);
        assert_eq!(store.last_error(), Some(StoreError::NotMigrating));
    }

    #[tokio::test]
    async fn jobs_run_one_at_a_time_in_order() {
        let store = Arc::new(MemoryStore::with_pcp("a", b"first").and_pcp("b", b"second"));
        let (enclave, entered, release) = GatedEnclave::new();
        let queue = Arc::new(JobQueue::new(NonZeroUsize::new(4).expect("non-zero")));
        let runner = tokio::spawn(
            Worker::new(
                Arc::clone(&queue),
                Arc::new(enclave),
                store.clone(),
                store.clone(),
            )
            .run(),
        );

        queue.push(job("a")).expect("room");
        queue.push(job("b")).expect("room");

        entered.notified().await;
        assert_eq!(store.outcome("a"), None, "a is still in the enclave");
        assert_eq!(store.outcome("b"), None, "b waits behind a");
        release.notify_one();

        entered.notified().await;
        assert_eq!(
            store.outcome("a"),
            Some(Outcome::Migrated("result/a".to_owned()))
        );
        assert_eq!(store.outcome("b"), None, "b is in the enclave now");
        release.notify_one();

        while store.outcome("b").is_none() {
            tokio::task::yield_now().await;
        }
        assert_eq!(queue.queued(), 0);
        runner.abort();
    }

    #[test]
    fn a_job_names_its_pcp() {
        let Job { object_key, .. } = job("a");
        assert_eq!(object_key, "pcp/a");
    }
}
