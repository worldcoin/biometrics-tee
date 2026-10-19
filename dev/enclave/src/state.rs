//! Boot-scoped state owned by the enclave.

/// The sandboxed worker as the enclave's operations see it.
pub trait Worker: Send + Sync {
    /// Exits the enclave if the worker died; must not wait for an in-flight request.
    fn check_alive(&self);
}

/// State fixed for the life of the enclave.
pub struct EnclaveState {
    worker: Box<dyn Worker>,
}

impl EnclaveState {
    /// Takes the worker launched before the async runtime started.
    #[must_use]
    pub fn new(worker: Box<dyn Worker>) -> Self {
        Self { worker }
    }

    /// Exits the enclave if the worker died.
    pub fn check_worker(&self) {
        self.worker.check_alive();
    }
}

#[cfg(target_os = "linux")]
impl Worker for std::sync::Mutex<tabernaculum::Worker> {
    fn check_alive(&self) {
        tabernaculum::check_alive_if_idle(self);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::{EnclaveState, Worker};

    /// Counts liveness checks instead of supervising a process.
    #[derive(Default)]
    pub struct FakeWorker {
        pub checks: Arc<AtomicUsize>,
    }

    impl Worker for FakeWorker {
        fn check_alive(&self) {
            self.checks.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub fn state() -> Arc<EnclaveState> {
        Arc::new(EnclaveState::new(Box::new(FakeWorker::default())))
    }

    #[test]
    fn checking_the_worker_reaches_it() {
        let worker = FakeWorker::default();
        let checks = Arc::clone(&worker.checks);
        let state = EnclaveState::new(Box::new(worker));

        state.check_worker();

        assert_eq!(checks.load(Ordering::SeqCst), 1);
    }
}
