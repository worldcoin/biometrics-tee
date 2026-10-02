//! Readiness, cached so frequent probes do not each cost a vsock round trip.

use std::{sync::Arc, time::Duration};

use tokio::{sync::Mutex, time::Instant};

use crate::enclave::EnclaveClient;

/// How long a readiness result is reused; short against the probe period, long against bursts.
const READINESS_TTL: Duration = Duration::from_secs(2);

/// The host's readiness: its enclave answers.
pub struct Readiness {
    enclave_client: Arc<dyn EnclaveClient>,
    last: Mutex<Option<(Instant, bool)>>,
}

impl Readiness {
    /// Creates an empty cache; the first check reaches the enclave.
    #[must_use]
    pub fn new(enclave_client: Arc<dyn EnclaveClient>) -> Self {
        Self {
            enclave_client,
            last: Mutex::new(None),
        }
    }

    /// Whether the host may take traffic. Concurrent callers share one check.
    pub async fn is_ready(&self) -> bool {
        let mut last = self.last.lock().await;
        if let Some((checked_at, ready)) = *last
            && checked_at.elapsed() < READINESS_TTL
        {
            return ready;
        }

        let ready = match self.enclave_client.health().await {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(?error, dependency = "enclave", "readiness check failed");
                false
            }
        };
        *last = Some((Instant::now(), ready));
        ready
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::{READINESS_TTL, Readiness};
    use crate::test_support::CountingEnclave;

    #[tokio::test(start_paused = true)]
    async fn a_result_is_reused_within_the_ttl() {
        let enclave = Arc::new(CountingEnclave::default());
        let readiness = Readiness::new(enclave.clone());

        assert!(readiness.is_ready().await);
        assert!(readiness.is_ready().await);

        assert_eq!(enclave.health_calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn the_enclave_is_asked_again_after_the_ttl() {
        let enclave = Arc::new(CountingEnclave::default());
        let readiness = Readiness::new(enclave.clone());

        assert!(readiness.is_ready().await);
        tokio::time::advance(READINESS_TTL + Duration::from_millis(1)).await;
        assert!(readiness.is_ready().await);

        assert_eq!(enclave.health_calls(), 2);
    }
}
