//! Readiness, cached so frequent probes do not each cost a vsock round trip and an S3 call.

use std::{sync::Arc, time::Duration};

use tokio::{sync::Mutex, time::Instant};

use crate::{enclave::EnclaveClient, store::BlobStore};

/// How long a readiness result is reused; short against the probe period, long against bursts.
const READINESS_TTL: Duration = Duration::from_secs(2);

/// The host's readiness: its enclave and bucket both answer. Without either every job would
/// fail, so the host leaves the Service rather than taking them.
pub struct Readiness {
    enclave_client: Arc<dyn EnclaveClient>,
    blob_store: Arc<dyn BlobStore>,
    last: Mutex<Option<(Instant, bool)>>,
}

impl Readiness {
    /// Creates an empty cache; the first check reaches every dependency.
    #[must_use]
    pub fn new(enclave_client: Arc<dyn EnclaveClient>, blob_store: Arc<dyn BlobStore>) -> Self {
        Self {
            enclave_client,
            blob_store,
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

        let ready = self.check().await;
        *last = Some((Instant::now(), ready));
        ready
    }

    async fn check(&self) -> bool {
        let (enclave, blobs) =
            tokio::join!(self.enclave_client.health(), self.blob_store.check_ready());

        if let Err(error) = &enclave {
            tracing::warn!(?error, dependency = "enclave", "readiness check failed");
        }
        if let Err(error) = &blobs {
            tracing::warn!(%error, dependency = "s3", "readiness check failed");
        }
        enclave.is_ok() && blobs.is_ok()
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::{READINESS_TTL, Readiness};
    use crate::test_support::{CountingEnclave, FailingStore, HealthyStore, StubEnclave};

    fn healthy(enclave: Arc<CountingEnclave>) -> Readiness {
        Readiness::new(enclave, Arc::new(HealthyStore))
    }

    #[tokio::test(start_paused = true)]
    async fn a_result_is_reused_within_the_ttl() {
        let enclave = Arc::new(CountingEnclave::default());
        let readiness = healthy(enclave.clone());

        assert!(readiness.is_ready().await);
        assert!(readiness.is_ready().await);

        assert_eq!(enclave.health_calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn the_dependencies_are_asked_again_after_the_ttl() {
        let enclave = Arc::new(CountingEnclave::default());
        let readiness = healthy(enclave.clone());

        assert!(readiness.is_ready().await);
        tokio::time::advance(READINESS_TTL + Duration::from_millis(1)).await;
        assert!(readiness.is_ready().await);

        assert_eq!(enclave.health_calls(), 2);
    }

    /// Without S3 every job would fail, so the host must leave the Service.
    #[tokio::test]
    async fn an_unreachable_bucket_makes_the_host_unready() {
        let readiness = Readiness::new(Arc::new(StubEnclave::default()), Arc::new(FailingStore));

        assert!(!readiness.is_ready().await);
    }
}
