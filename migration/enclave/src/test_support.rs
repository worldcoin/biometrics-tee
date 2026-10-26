//! Attestors that stand in for the Nitro Secure Module in tests.

use std::sync::atomic::{AtomicUsize, Ordering};

use aws_sdk_kms::{
    Client,
    config::{BehaviorVersion, Region},
};
use aws_smithy_runtime_api::client::{
    http::{
        HttpConnector, HttpConnectorFuture, SharedHttpClient, SharedHttpConnector, http_client_fn,
    },
    orchestrator::HttpRequest,
};
use di_migration_enclave_primitives as enclave_primitives;
use world_id_primitives::{EdDSAPrivateKey, EdDSAPublicKey};

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
    state_with_issuer_pubkey(EdDSAPrivateKey::from_bytes([7u8; 32]).public())
}

/// Boot state that verifies credentials against `issuer_pubkey`.
pub fn state_with_issuer_pubkey(issuer_pubkey: EdDSAPublicKey) -> crate::state::EnclaveState {
    crate::state::EnclaveState::generate(
        std::sync::Arc::new(CountingAttestor::default()),
        issuer_pubkey,
        test_key_wrapper(),
    )
    .expect("should generate a key")
}

/// A syntactically valid wrapper for tests that finish before making a KMS request.
fn test_key_wrapper() -> crate::kms::KeyWrapper {
    const KEY_ARN: &str =
        "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000001";
    let config = aws_sdk_kms::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .http_client(test_http_client())
        .build();
    crate::kms::KeyWrapper::new(&Client::from_conf(config), KEY_ARN.to_owned())
        .expect("test key ARN should be valid")
}

#[derive(Debug)]
struct UnexpectedKmsConnector;

impl HttpConnector for UnexpectedKmsConnector {
    fn call(&self, _request: HttpRequest) -> HttpConnectorFuture {
        panic!("this test must not call KMS")
    }
}

fn test_http_client() -> SharedHttpClient {
    let connector = SharedHttpConnector::new(UnexpectedKmsConnector);
    http_client_fn(move |_, _| connector.clone())
}
