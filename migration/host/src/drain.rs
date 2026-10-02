//! Graceful drain: after SIGTERM the host leaves the Service but finishes the jobs it holds.

use std::time::Duration;

use crate::queue::JobQueue;

/// How often the drain checks whether the queue has emptied; short against job durations.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// How a drain ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Every waiting and running job finished.
    Idle,
    /// The deadline passed with jobs left; they read as `timeout` once their deadlines pass.
    TimedOut {
        /// Jobs still waiting or running.
        remaining: usize,
    },
}

/// Waits until `queue` holds no jobs, or `timeout` passes.
pub async fn wait_for_idle(queue: &JobQueue, timeout: Duration) -> Outcome {
    let idle = async {
        while queue.queued() > 0 {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    };
    match tokio::time::timeout(timeout, idle).await {
        Ok(()) => Outcome::Idle,
        Err(_) => Outcome::TimedOut {
            remaining: queue.queued(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, sync::Arc, time::Duration};

    use super::{Outcome, wait_for_idle};
    use crate::{queue::JobQueue, test_support::job};

    fn queue() -> Arc<JobQueue> {
        Arc::new(JobQueue::new(NonZeroUsize::new(4).expect("non-zero")))
    }

    #[tokio::test(start_paused = true)]
    async fn an_empty_queue_is_idle_at_once() {
        assert_eq!(
            wait_for_idle(&queue(), Duration::from_secs(1)).await,
            Outcome::Idle
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_drain_waits_for_the_running_job() {
        let queue = queue();
        queue.push(job(1)).expect("room");
        let running = queue.next().await;
        let finisher = tokio::spawn({
            let queue = Arc::clone(&queue);
            async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                queue.finish(&running.job_id);
            }
        });

        assert_eq!(
            wait_for_idle(&queue, Duration::from_secs(60)).await,
            Outcome::Idle
        );
        finisher.await.expect("should join");
    }

    #[tokio::test(start_paused = true)]
    async fn the_deadline_bounds_the_drain() {
        let queue = queue();
        queue.push(job(1)).expect("room");
        queue.push(job(2)).expect("room");

        assert_eq!(
            wait_for_idle(&queue, Duration::from_secs(60)).await,
            Outcome::TimedOut { remaining: 2 }
        );
    }
}
