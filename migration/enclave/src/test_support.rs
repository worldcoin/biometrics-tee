//! Attestors that stand in for the Nitro Secure Module in tests.

use std::sync::atomic::{AtomicUsize, Ordering};

use di_migration_enclave_primitives as enclave_primitives;

use crate::attestation::Attestor;

/// Returns a distinct document per call, embedding the attested key.
#[derive(Default)]
pub struct CountingAttestor {
    calls: AtomicUsize,
}

impl CountingAttestor {
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Attestor for CountingAttestor {
    fn attest_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, enclave_primitives::Error> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let mut document = public_key.to_vec();
        document.extend_from_slice(&call.to_be_bytes());
        Ok(document)
    }
}

/// Succeeds `successes` times, then fails every call.
pub struct FailsAfterSuccessesAttestor {
    successes: usize,
    calls: AtomicUsize,
}

impl FailsAfterSuccessesAttestor {
    pub const fn new(successes: usize) -> Self {
        Self {
            successes,
            calls: AtomicUsize::new(0),
        }
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Attestor for FailsAfterSuccessesAttestor {
    fn attest_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, enclave_primitives::Error> {
        if self.calls.fetch_add(1, Ordering::SeqCst) < self.successes {
            Ok(public_key.to_vec())
        } else {
            Err(enclave_primitives::Error::Internal)
        }
    }
}

/// Boot state attested by a [`CountingAttestor`].
pub fn state() -> crate::state::EnclaveState {
    crate::state::EnclaveState::generate(std::sync::Arc::new(CountingAttestor::default()))
        .expect("should generate a key")
}
