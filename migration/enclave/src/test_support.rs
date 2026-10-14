//! Attestors that stand in for the Nitro Secure Module in tests.

use std::{
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
};

use ark_babyjubjub::{EdwardsAffine, Fq};
use di_migration_enclave_primitives as enclave_primitives;
use world_id_primitives::EdDSAPublicKey;

use crate::attestation::Attestor;

/// Staging issuer pubkey coordinates for tests.
const STAGING_ISSUER_PUBKEY_X: &str =
    "8764755626041608914298444081069238835505190105048545592330271001420004184714";
const STAGING_ISSUER_PUBKEY_Y: &str =
    "21113891529244736453398517984414846376859272077465756596625387480138387442766";

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
    state_with_issuer_pubkey(staging_issuer_pubkey())
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
        std::sync::Arc::new(CountingAttestor::default()),
        issuer_pubkey,
        credential_verification_enabled,
    )
    .expect("should generate a key")
}

fn staging_issuer_pubkey() -> EdDSAPublicKey {
    EdDSAPublicKey {
        pk: EdwardsAffine {
            x: Fq::from_str(STAGING_ISSUER_PUBKEY_X)
                .expect("STAGING_ISSUER_PUBKEY_X is a valid decimal Fq element"),
            y: Fq::from_str(STAGING_ISSUER_PUBKEY_Y)
                .expect("STAGING_ISSUER_PUBKEY_Y is a valid decimal Fq element"),
        },
    }
}
