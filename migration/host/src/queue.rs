//! The bounded in-memory job queue. Jobs die with the enclave's boot key, so durability would
//! buy nothing; the cap is a safety net, since the API admits against the fleet's capacity.

use std::{
    collections::{HashMap, VecDeque},
    num::NonZeroUsize,
    sync::Mutex,
    time::Instant,
};

use di_migration_primitives::{JobId, host_api::JobRequest};
use telemetry_batteries::reexports::metrics;
use tokio::sync::Notify;

/// How a push was handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The job joined the queue.
    Queued,
    /// The job is already queued or running; a retried dispatch is not run twice.
    Duplicate,
}

/// The queue is at its cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Full;

#[derive(Default)]
struct State {
    waiting: VecDeque<JobRequest>,
    /// Waiting and running job IDs: what dedup and the cap count.
    known: HashMap<JobId, Instant>,
}

/// Jobs the API dispatched, waiting for or held by the single job runner.
pub struct JobQueue {
    state: Mutex<State>,
    ready: Notify,
    capacity: NonZeroUsize,
}

impl JobQueue {
    /// Creates an empty queue holding at most `capacity` waiting and running jobs.
    #[must_use]
    pub fn new(capacity: NonZeroUsize) -> Self {
        let queue = Self {
            state: Mutex::new(State::default()),
            ready: Notify::new(),
            capacity,
        };
        Self::record_metrics(&State::default());
        queue
    }

    /// Adds `job` unless it is already known.
    ///
    /// # Errors
    ///
    /// [`Full`] when the queue is at its cap.
    pub fn push(&self, job: JobRequest) -> Result<Admission, Full> {
        let mut state = self.lock();
        if state.known.contains_key(&job.job_id) {
            return Ok(Admission::Duplicate);
        }
        if state.known.len() >= self.capacity.get() {
            return Err(Full);
        }
        state.known.insert(job.job_id.clone(), Instant::now());
        state.waiting.push_back(job);
        Self::record_metrics(&state);
        drop(state);
        // `notify_one` stores a permit, so a job runner that is not waiting yet still wakes.
        self.ready.notify_one();
        Ok(Admission::Queued)
    }

    /// Waits for the oldest job. It stays counted until [`Self::finish`].
    pub async fn next(&self) -> JobRequest {
        loop {
            let next = self.lock().waiting.pop_front();
            if let Some(job) = next {
                return job;
            }
            self.ready.notified().await;
        }
    }

    /// Releases a job taken with [`Self::next`].
    pub fn finish(&self, job_id: &JobId) {
        let mut state = self.lock();
        if state.known.remove(job_id).is_some() {
            Self::record_metrics(&state);
        }
    }

    /// Refreshes the gauges, including age as time passes without queue transitions.
    pub fn refresh_metrics(&self) {
        Self::record_metrics(&self.lock());
    }

    /// Waiting plus running jobs.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.lock().known.len()
    }

    /// The cap the API admits against.
    #[must_use]
    pub const fn capacity(&self) -> NonZeroUsize {
        self.capacity
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // Nothing panics while holding the lock, so a poisoned one still holds consistent state.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn record_metrics(state: &State) {
        metrics::gauge!("migration.host.queued_requests").set(state.known.len() as f64);
        let oldest_age_seconds = state
            .known
            .values()
            .min()
            .map_or(0.0, |enqueued_at| enqueued_at.elapsed().as_secs_f64());
        metrics::gauge!("migration.host.oldest_queued_job_age_seconds")
            .set(oldest_age_seconds);
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::{Admission, Full, JobQueue};
    use crate::test_support::job;

    fn queue(capacity: usize) -> JobQueue {
        JobQueue::new(NonZeroUsize::new(capacity).expect("non-zero"))
    }

    #[tokio::test]
    async fn jobs_come_out_in_arrival_order() {
        let queue = queue(4);
        queue.push(job(1)).expect("room");
        queue.push(job(2)).expect("room");

        assert_eq!(queue.next().await.job_id, job(1).job_id);
        assert_eq!(queue.next().await.job_id, job(2).job_id);
    }

    /// A retried dispatch, waiting or running, must not run the job twice.
    #[tokio::test]
    async fn a_known_job_is_a_duplicate_until_it_finishes() {
        let queue = queue(4);
        assert_eq!(queue.push(job(1)), Ok(Admission::Queued));
        assert_eq!(queue.push(job(1)), Ok(Admission::Duplicate));

        let running = queue.next().await;
        assert_eq!(queue.push(job(1)), Ok(Admission::Duplicate));

        queue.finish(&running.job_id);
        assert_eq!(queue.push(job(1)), Ok(Admission::Queued));
    }

    /// The running job counts, so the cap bounds everything the host holds.
    #[tokio::test]
    async fn the_cap_counts_the_running_job() {
        let queue = queue(1);
        queue.push(job(1)).expect("room");
        let running = queue.next().await;

        assert_eq!(queue.queued(), 1);
        assert_eq!(queue.push(job(2)), Err(Full));

        queue.finish(&running.job_id);
        assert_eq!(queue.queued(), 0);
        assert_eq!(queue.push(job(2)), Ok(Admission::Queued));
    }

    #[tokio::test]
    async fn a_waiting_worker_wakes_on_push() {
        let queue = std::sync::Arc::new(queue(4));
        let waiter = tokio::spawn({
            let queue = std::sync::Arc::clone(&queue);
            async move { queue.next().await }
        });
        tokio::task::yield_now().await;

        queue.push(job(1)).expect("room");

        assert_eq!(waiter.await.expect("should join").job_id, job(1).job_id);
    }
}
