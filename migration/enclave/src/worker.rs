//! The sandboxed biometric worker as the enclave's operations see it.

/// The worker launched under Minijail before the async runtime started.
pub trait Worker: Send + Sync {
    /// Exits the enclave if the worker died; must not wait for an in-flight request.
    fn check_alive(&self);
}

#[cfg(target_os = "linux")]
impl Worker for std::sync::Mutex<tabernaculum::Worker> {
    fn check_alive(&self) {
        tabernaculum::check_alive_if_idle(self);
    }
}
