//! Attestors that stand in for the Nitro Secure Module in tests.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use di_migration_enclave_primitives as enclave_primitives;
use world_id_primitives::{EdDSAPrivateKey, EdDSAPublicKey};

use crate::{attestation::Attestor, worker::Worker};

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

/// Boot state attested by a [`CountingAttestor`].
pub fn state() -> crate::state::EnclaveState {
    state_with_issuer_pubkey(EdDSAPrivateKey::from_bytes([7u8; 32]).public())
}

/// Boot state that verifies credentials against `issuer_pubkey`.
pub fn state_with_issuer_pubkey(issuer_pubkey: EdDSAPublicKey) -> crate::state::EnclaveState {
    state_with_issuer_pubkey_and_credential_verification(issuer_pubkey, true)
}

/// Boot state with an explicit credential-verification feature flag.
pub fn state_with_issuer_pubkey_and_credential_verification(
    issuer_pubkey: EdDSAPublicKey,
    credential_verification_enabled: bool,
) -> crate::state::EnclaveState {
    crate::state::EnclaveState::generate(
        Arc::new(CountingAttestor::default()),
        issuer_pubkey,
        credential_verification_enabled,
        Box::new(FakeWorker::default()),
    )
    .expect("should generate a key")
}

/// Boot state supervising `worker`.
pub fn state_with_worker(worker: FakeWorker) -> crate::state::EnclaveState {
    crate::state::EnclaveState::generate(
        Arc::new(CountingAttestor::default()),
        EdDSAPrivateKey::from_bytes([7u8; 32]).public(),
        true,
        Box::new(worker),
    )
    .expect("should generate a key")
}
