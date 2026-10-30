//! Nitro Secure Module attestation.

use std::sync::Arc;
use std::time::Duration;

use pontifex::{AttestationDoc, SecureModule};
use selfie_enrollment_enclave_types as enclave_types;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// How long after an attest before the background task refreshes the document.
pub const MAX_CACHED_AGE: Duration = Duration::from_mins(10);

/// After a failed refresh, if the last successful attest is at least this old, the
/// refresh task exits so `main` takes down the enclave. Aligned with the client
/// default `max_attestation_age_millis` (1h).
pub const MAX_SERVABLE_AGE: Duration = Duration::from_hours(1);

/// Produces documents attesting a raw signing key or a channel-key commitment.
pub trait Attestor: Send + Sync {
    /// Attests `public_key` in the document's `public_key` field.
    /// # Errors
    ///
    /// Returns [`enclave_types::Error::Unavailable`] when the module rejects the request.
    fn attest_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, enclave_types::Error>;
}

/// [`Attestor`] backed by the real Nitro Secure Module.
#[derive(Debug, Clone)]
pub struct NsmAttestor;

impl Attestor for NsmAttestor {
    fn attest_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, enclave_types::Error> {
        let secure_module = SecureModule::try_global().ok_or(enclave_types::Error::Unavailable)?;

        secure_module
            .raw_attest(None::<Vec<u8>>, None::<Vec<u8>>, Some(public_key.to_vec()))
            .map_err(|error| {
                tracing::error!(?error, "failed to attest public key");
                enclave_types::Error::Unavailable
            })
    }
}

impl selfie_enrollment_identity::CaptureAttestor for NsmAttestor {
    fn attest(
        &self,
        nonce: &[u8; selfie_enrollment_identity::NONCE_BYTES],
        user_data: &[u8; selfie_enrollment_identity::USER_DATA_BYTES],
    ) -> Result<Vec<u8>, selfie_enrollment_identity::AttestationFailed> {
        SecureModule::try_global()
            .ok_or(selfie_enrollment_identity::AttestationFailed)?
            .raw_attest(
                Some(user_data.to_vec()),
                Some(nonce.to_vec()),
                None::<Vec<u8>>,
            )
            .map_err(|_| selfie_enrollment_identity::AttestationFailed)
    }
}

/// A cached document and when it was produced.
struct CachedAttestation {
    document: Vec<u8>,
    attested_at: Instant,
}

/// A boot-scoped key binding (raw key or commitment) and its latest attestation document.
///
/// Call [`Self::start_refresh`] once; the returned handle must be supervised (see `main`).
/// Until then the construction-time document is served. Readers always get the last
/// successful document immediately.
pub struct AttestedKey {
    attestor: Arc<dyn Attestor>,
    public_key: Vec<u8>,
    max_age: Duration,
    cached_attestation: Arc<Mutex<CachedAttestation>>,
    refresh_started: bool,
}

impl AttestedKey {
    /// Constructs a new `AttestedKey` for `public_key` using the given `attestor`.
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
            cached_attestation: Arc::new(Mutex::new(CachedAttestation {
                document,
                attested_at: Instant::now(),
            })),
            refresh_started: false,
        })
    }

    /// Starts the background refresh task.
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
        let cache = Arc::clone(&self.cached_attestation);

        tokio::spawn(async move {
            let mut delay = max_age;
            loop {
                tokio::time::sleep(delay).await;
                delay = max_age;

                let attestor = Arc::clone(&attestor);
                let key = public_key.clone();
                let result =
                    tokio::task::spawn_blocking(move || attestor.attest_public_key(&key)).await;

                match result {
                    Ok(Ok(document)) => {
                        let mut cached = cache.lock().await;
                        cached.document = document;
                        cached.attested_at = Instant::now();
                    }
                    Ok(Err(error)) => {
                        tracing::error!(?error, "background attestation refresh failed");
                        delay = Duration::from_secs(30).min(max_age);
                        let age = cache.lock().await.attested_at.elapsed();
                        if age >= MAX_SERVABLE_AGE {
                            tracing::error!(
                                ?age,
                                max = ?MAX_SERVABLE_AGE,
                                "attestation document exceeded max servable age; exiting refresh task"
                            );
                            return;
                        }
                    }
                    Err(error) => {
                        // spawn_blocking task panicked
                        tracing::error!(
                            ?error,
                            "background attestation spawn_blocking join failed"
                        );
                        return;
                    }
                }
            }
        })
    }

    /// Returns the cached attestation document (may be older than `max_age` while a refresh runs).
    pub async fn document(&self) -> Vec<u8> {
        self.cached_attestation.lock().await.document.clone()
    }
}

/// Connects to the Nitro Secure Module. Called before serving so a missing or broken device fails the boot.
///
/// # Errors
///
/// Returns an error when the NSM device cannot be opened.
pub async fn connect() -> anyhow::Result<&'static SecureModule> {
    Ok(SecureModule::try_init_global().await?)
}

/// Whether every PCR in a document is zeroed.
///
/// True for a `--debug-mode` enclave, whose measurements say nothing about the image
/// that produced them.
#[must_use]
pub fn has_zeroed_measurements(document: &AttestationDoc) -> bool {
    !document.pcrs.is_empty()
        && document
            .pcrs
            .values()
            .all(|pcr| pcr.iter().all(|&b| b == 0))
}

/// Logs the measurements a client will pin this enclave against.
///
/// Emitted once at boot so the running image is identifiable from logs alone, without
/// an attestation fetch.
///
/// Clients pin `pcr0`, which is a hash of the whole image. `pcr1` (kernel and boot ramfs) and
/// `pcr2` (application) are logged for introspection.
pub fn log_boot_measurements(document: &AttestationDoc) {
    if has_zeroed_measurements(document) {
        tracing::warn!(
            module_id = %document.module_id,
            "enclave is running in debug mode: measurements are zeroed and attestations \
             are not verifiable against a released image"
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
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestAttestor {
        calls: AtomicUsize,
        attempts: tokio::sync::mpsc::UnboundedSender<Instant>,
        recover: bool,
    }

    impl Attestor for TestAttestor {
        fn attest_public_key(&self, _: &[u8]) -> Result<Vec<u8>, enclave_types::Error> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            self.attempts.send(Instant::now()).unwrap();
            if call == 0 || (self.recover && call > 1) {
                Ok(call.to_le_bytes().to_vec())
            } else {
                Err(enclave_types::Error::Unavailable)
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn failed_refresh_retries_soon_then_resumes_normal_interval() {
        let (attempts, mut received) = tokio::sync::mpsc::unbounded_channel();
        let mut key = AttestedKey::new(
            Arc::new(TestAttestor {
                calls: AtomicUsize::new(0),
                attempts,
                recover: true,
            }),
            vec![1],
            MAX_CACHED_AGE,
        )
        .unwrap();
        let initial = received.recv().await.unwrap();
        let refresh = key.start_refresh();
        let failed = received.recv().await.unwrap();
        let retried = received.recv().await.unwrap();
        let normal = received.recv().await.unwrap();
        refresh.abort();

        assert_eq!(failed - initial, MAX_CACHED_AGE);
        assert_eq!(retried - failed, Duration::from_secs(30));
        assert_eq!(normal - retried, MAX_CACHED_AGE);
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_failures_still_stop_at_max_servable_age() {
        let (attempts, _received) = tokio::sync::mpsc::unbounded_channel();
        let mut key = AttestedKey::new(
            Arc::new(TestAttestor {
                calls: AtomicUsize::new(0),
                attempts,
                recover: false,
            }),
            vec![1],
            MAX_CACHED_AGE,
        )
        .unwrap();
        let initial = key.document().await;
        let started = Instant::now();
        key.start_refresh().await.unwrap();
        assert_eq!(started.elapsed(), MAX_SERVABLE_AGE);
        assert_eq!(key.document().await, initial);
    }
}
