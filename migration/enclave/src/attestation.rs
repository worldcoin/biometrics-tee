//! Nitro Secure Module attestation of the boot's channel key.

use std::{sync::Arc, time::Duration};

use di_migration_enclave_types as enclave_types;
use pontifex::{AttestationDoc, SecureModule};
use tokio::{sync::Mutex, task::JoinHandle, time::Instant};

/// How long after an attest before the background task refreshes the document.
pub const MAX_CACHED_AGE: Duration = Duration::from_mins(10);

/// After a failed refresh, if the last successful attest is at least this old, the refresh task
/// exits so `main` takes down the enclave rather than serving a document apps will reject.
pub const MAX_SERVABLE_AGE: Duration = Duration::from_hours(1);

/// Produces documents attesting a public key, or a commitment to one.
pub trait Attestor: Send + Sync {
    /// Attests `public_key` in the document's `public_key` field.
    ///
    /// # Errors
    ///
    /// [`enclave_types::Error::Internal`] when the module rejects the request.
    fn attest_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, enclave_types::Error>;
}

/// [`Attestor`] backed by the real Nitro Secure Module.
#[derive(Debug, Clone, Copy)]
pub struct NsmAttestor;

impl Attestor for NsmAttestor {
    fn attest_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, enclave_types::Error> {
        let secure_module = SecureModule::try_global().ok_or_else(|| {
            tracing::error!("Nitro Secure Module is not initialized");
            enclave_types::Error::Internal
        })?;

        secure_module
            .raw_attest(None::<Vec<u8>>, None::<Vec<u8>>, Some(public_key.to_vec()))
            .map_err(|error| {
                tracing::error!(?error, dependency = "nsm", "failed to attest public key");
                enclave_types::Error::Internal
            })
    }
}

/// A cached document and when it was produced.
struct CachedAttestation {
    document: Vec<u8>,
    attested_at: Instant,
}

/// A boot-scoped key binding and its latest attestation document.
///
/// Call [`Self::start_refresh`] once and supervise the handle; until then the construction-time
/// document is served. Readers always get the last successful document at once.
pub struct AttestedKey {
    attestor: Arc<dyn Attestor>,
    public_key: Vec<u8>,
    max_age: Duration,
    cached: Arc<Mutex<CachedAttestation>>,
    refresh_started: bool,
}

impl AttestedKey {
    /// Attests `public_key` once, so a broken module fails the boot.
    ///
    /// # Errors
    ///
    /// Propagates the [`Attestor`] failure.
    pub fn new(
        attestor: Arc<dyn Attestor>,
        public_key: Vec<u8>,
        max_age: Duration,
    ) -> Result<Self, enclave_types::Error> {
        let document = attestor.attest_public_key(&public_key)?;

        Ok(Self {
            attestor,
            public_key,
            max_age,
            cached: Arc::new(Mutex::new(CachedAttestation {
                document,
                attested_at: Instant::now(),
            })),
            refresh_started: false,
        })
    }

    /// Starts re-attesting every `max_age`. The task ends only when the served document grows
    /// older than [`MAX_SERVABLE_AGE`], which must take the enclave down.
    ///
    /// # Panics
    ///
    /// Panics if called more than once.
    pub fn start_refresh(&mut self) -> JoinHandle<()> {
        assert!(!self.refresh_started, "attestation refresh already started");
        self.refresh_started = true;

        let attestor = Arc::clone(&self.attestor);
        let public_key = self.public_key.clone();
        let max_age = self.max_age;
        let cache = Arc::clone(&self.cached);

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(max_age).await;

                let attestor = Arc::clone(&attestor);
                let key = public_key.clone();
                match tokio::task::spawn_blocking(move || attestor.attest_public_key(&key)).await {
                    Ok(Ok(document)) => {
                        let mut cached = cache.lock().await;
                        cached.document = document;
                        cached.attested_at = Instant::now();
                    }
                    Ok(Err(_)) => {
                        let age = cache.lock().await.attested_at.elapsed();
                        if age >= MAX_SERVABLE_AGE {
                            tracing::error!(
                                ?age,
                                "attestation document exceeded its max servable age"
                            );
                            return;
                        }
                        tracing::warn!(
                            ?age,
                            "attestation refresh failed; serving the last document"
                        );
                    }
                    Err(error) => {
                        tracing::error!(%error, "attestation refresh task panicked");
                        return;
                    }
                }
            }
        })
    }

    /// The latest successful document.
    pub async fn document(&self) -> Vec<u8> {
        self.cached.lock().await.document.clone()
    }
}

/// Connects to the Nitro Secure Module; called before serving so a missing device fails the boot.
///
/// # Errors
///
/// The NSM device cannot be opened.
pub async fn connect() -> anyhow::Result<&'static SecureModule> {
    Ok(SecureModule::try_init_global().await?)
}

/// Whether every PCR is zeroed, as in a `--debug-mode` enclave whose measurements prove nothing.
#[must_use]
pub fn has_zeroed_measurements(document: &AttestationDoc) -> bool {
    !document.pcrs.is_empty()
        && document
            .pcrs
            .values()
            .all(|pcr| pcr.iter().all(|&byte| byte == 0))
}

/// Logs the measurements apps pin this enclave against, once at boot, so the running image is
/// identifiable from logs alone.
pub fn log_boot_measurements(document: &AttestationDoc) {
    if has_zeroed_measurements(document) {
        tracing::warn!(
            module_id = %document.module_id,
            "enclave runs in debug mode: measurements are zeroed and attestations are unverifiable"
        );
        return;
    }

    let measurement = |index: usize| {
        document
            .pcrs
            .get(&index)
            .map(hex::encode)
            .unwrap_or_default()
    };
    tracing::info!(
        module_id = %document.module_id,
        pcr0 = %measurement(0),
        pcr1 = %measurement(1),
        pcr2 = %measurement(2),
        "attested enclave measurements"
    );
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::{AttestedKey, Attestor, MAX_SERVABLE_AGE};
    use crate::test_support::{CountingAttestor, FailsAfterSuccessesAttestor};

    fn key(attestor: Arc<dyn Attestor>, max_age: Duration) -> AttestedKey {
        AttestedKey::new(attestor, b"a-public-key".to_vec(), max_age).expect("should attest")
    }

    #[tokio::test]
    async fn reads_inside_the_window_do_not_reach_the_attestor() {
        let attestor = Arc::new(CountingAttestor::default());
        let cached = key(attestor.clone(), Duration::from_hours(1));

        assert_eq!(cached.document().await, cached.document().await);
        assert_eq!(attestor.calls(), 1, "only the one at construction");
    }

    #[tokio::test]
    async fn the_document_is_refreshed_after_max_age() {
        let attestor = Arc::new(CountingAttestor::default());
        let mut cached = key(attestor.clone(), Duration::from_millis(20));
        let _refresh = cached.start_refresh();
        let before = cached.document().await;

        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_ne!(cached.document().await, before);
        assert!(attestor.calls() >= 2);
    }

    #[tokio::test]
    async fn a_failed_refresh_keeps_serving_the_last_document() {
        let attestor = Arc::new(FailsAfterSuccessesAttestor::new(1));
        let mut cached = key(attestor.clone(), Duration::from_millis(20));
        let refresh = cached.start_refresh();
        let before = cached.document().await;

        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(attestor.calls() >= 2, "a refresh should have been tried");
        assert_eq!(cached.document().await, before);
        assert!(!refresh.is_finished());
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_stops_once_the_document_is_too_old_to_serve() {
        let attestor = Arc::new(FailsAfterSuccessesAttestor::new(1));
        let mut cached = key(attestor.clone(), Duration::from_secs(1));
        let refresh = cached.start_refresh();

        tokio::task::yield_now().await;
        tokio::time::advance(MAX_SERVABLE_AGE).await;

        // Awaiting the handle lets the runtime idle, which drives the blocking attest to the end.
        refresh.await.expect("refresh task should not panic");
        assert!(attestor.calls() >= 2);
    }
}
