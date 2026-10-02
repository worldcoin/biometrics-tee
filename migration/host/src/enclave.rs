//! Client boundary between the host and enclave.

use std::{fmt::Write as _, time::Duration};

use async_trait::async_trait;
use di_migration_enclave_types::{
    self as enclave_types, GetEncryptionKeyRequest, HealthRequest, KeyAttestation,
};
use pontifex::{Request, client::ConnectionDetails};
use tokio::time::timeout;

/// Probes and attestation reads must not hang behind a wedged enclave.
const CONTROL_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Failures while calling an enclave operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The Pontifex connection or wire operation failed.
    Transport(String),
    /// The enclave returned a structured operation error.
    Operation(enclave_types::Error),
    /// The enclave did not answer within the request deadline.
    Timeout,
}

/// Operations the host requires from the enclave.
#[async_trait]
pub trait EnclaveClient: Send + Sync {
    /// Checks whether the enclave process is reachable and ready.
    async fn health(&self) -> Result<(), Error>;

    /// Returns this boot's channel key and its attestation.
    async fn encryption_key(&self) -> Result<KeyAttestation, Error>;
}

/// Pontifex-backed enclave client.
#[derive(Debug, Clone, Copy)]
pub struct PontifexEnclaveClient {
    connection: ConnectionDetails,
}

impl PontifexEnclaveClient {
    /// Creates a client for the provided enclave CID and Pontifex port.
    #[must_use]
    pub const fn new(cid: u32, port: u32) -> Self {
        Self {
            connection: ConnectionDetails::new(cid, port),
        }
    }

    /// Sends `request` under `deadline`, flattening the timeout, transport and operation layers.
    async fn call<R, T>(&self, request: R, deadline: Duration) -> Result<T, Error>
    where
        R: Request<Response = Result<T, enclave_types::Error>> + Sync,
    {
        timeout(deadline, pontifex::client::send(self.connection, &request))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|error| Error::Transport(error.to_string()))?
            .map_err(Error::Operation)
    }
}

#[async_trait]
impl EnclaveClient for PontifexEnclaveClient {
    async fn health(&self) -> Result<(), Error> {
        self.call(HealthRequest, CONTROL_REQUEST_TIMEOUT).await
    }

    async fn encryption_key(&self) -> Result<KeyAttestation, Error> {
        self.call(GetEncryptionKeyRequest, CONTROL_REQUEST_TIMEOUT)
            .await
    }
}

/// The boot's identity: hex of the channel key's Pontifex commitment, which the attestation
/// document carries, so a restarted enclave gets a new one.
///
/// Not the document's `module_id`: a job is bound to the key its PCP was sealed to, and the
/// commitment changes exactly with that key and is checkable against the attested `public_key`.
#[must_use]
pub fn enclave_id(public_key: &[u8]) -> String {
    pontifex::channel::public_key_commitment(public_key)
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

#[cfg(test)]
mod tests {
    use super::enclave_id;

    /// Pins the encoding: the API and app compare this string to the attested commitment.
    #[test]
    fn the_enclave_id_is_the_hex_commitment_of_the_key() {
        assert_eq!(
            enclave_id(b"key"),
            "77634addf9ae031e3d621410d643d1f13b7d426876627b53d89ea0f7bba71cfb"
        );
    }

    #[test]
    fn different_keys_get_different_enclave_ids() {
        assert_ne!(enclave_id(b"key-a"), enclave_id(b"key-b"));
    }
}
