//! Fail-closed enrollment client. Measurement and worker allowlists always come from the caller.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use pontifex::{
    ChannelConsumer, ChannelDomain, ResponseOpener,
    attestation::{PcrConfig, VerifiedAttestation, Verifier},
};
use selfie_enrollment_api_types::*;
use selfie_enrollment_sealed_types::{EmbeddingRequest, EmbeddingResult, WorkerIdentity};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[cfg(target_arch = "wasm32")]
pub mod browser;
#[cfg(not(target_arch = "wasm32"))]
pub mod native;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
    pub worker_sha384: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub endpoint: String,
    pub releases: Vec<Release>,
}
impl Config {
    pub fn validate(&self) -> Result<(), Error> {
        self.verifier()?;
        let url = url::Url::parse(&self.endpoint).map_err(|_| Error::Config)?;
        let local = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
        if (url.scheme() != "wss" && !(url.scheme() == "ws" && local))
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(Error::Config);
        }
        Ok(())
    }
    pub fn verifier(&self) -> Result<Verifier, Error> {
        if self.releases.is_empty() || self.releases.len() > 8 {
            return Err(Error::Config);
        }
        let configs = self
            .releases
            .iter()
            .map(|r| {
                let pcr0 = hash(&r.pcr0)?;
                let pcr1 = hash(&r.pcr1)?;
                let pcr2 = hash(&r.pcr2)?;
                hash(&r.worker_sha384)?;
                Ok(PcrConfig::new(pcr0)
                    .with_pcr(1, pcr1.to_vec())
                    .with_pcr(2, pcr2.to_vec()))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Verifier::new(configs, Duration::from_secs(3600)))
    }
}
fn hash(value: &str) -> Result<[u8; 48], Error> {
    if value.len() != 96
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Config);
    }
    let bytes: [u8; 48] = hex::decode(value)
        .map_err(|_| Error::Config)?
        .try_into()
        .map_err(|_| Error::Config)?;
    if bytes == [0; 48] {
        return Err(Error::Config);
    }
    Ok(bytes)
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid enrollment configuration")]
    Config,
    #[error("enclave or worker attestation rejected")]
    Attestation,
    #[error("invalid enrollment message")]
    Protocol,
    #[error("enrollment transport failed")]
    Transport,
    #[error("enrollment timed out or was cancelled")]
    Timeout,
    #[error("enrollment response authentication failed")]
    Authentication,
    #[error("enrollment host: {0}")]
    Host(ErrorCode),
}

/// Holds the verified boot key and attested worker identity.
pub struct VerifiedAssignment {
    attestation: VerifiedAttestation,
    consumer: ChannelConsumer,
    identity: WorkerIdentity,
}
impl VerifiedAssignment {
    pub fn verify(config: &Config, assignment: &Assignment) -> Result<Self, Error> {
        config.validate()?;
        if assignment.attestation.len() > MAX_CONTROL_BYTES || assignment.public_key.len() > 8192 {
            return Err(Error::Protocol);
        }
        let doc = STANDARD
            .decode(&assignment.attestation)
            .map_err(|_| Error::Protocol)?;
        let public_key = STANDARD
            .decode(&assignment.public_key)
            .map_err(|_| Error::Protocol)?;
        let (consumer, verified) = ChannelConsumer::from_attestation(
            ChannelDomain::new(CHANNEL_DOMAIN),
            &config.verifier()?,
            &doc,
            &public_key,
        )
        .map_err(|_| Error::Attestation)?;
        let identity = WorkerIdentity::decode(
            verified
                .document()
                .user_data
                .as_deref()
                .ok_or(Error::Attestation)?,
        )
        .map_err(|_| Error::Attestation)?;
        if !matches_release(
            &config.releases,
            &identity,
            std::array::from_fn(|index| {
                verified
                    .document()
                    .pcrs
                    .get(&index)
                    .map(|pcr| pcr.as_slice())
            }),
        ) {
            return Err(Error::Attestation);
        }
        Ok(Self {
            attestation: verified,
            consumer,
            identity,
        })
    }
    pub fn attestation(&self) -> &VerifiedAttestation {
        &self.attestation
    }
    pub fn consumer(&self) -> &ChannelConsumer {
        &self.consumer
    }
    pub fn worker(&self) -> &WorkerIdentity {
        &self.identity
    }
    fn seal(&self, image: Vec<u8>) -> Result<(Vec<u8>, PendingResult), Error> {
        let request = EmbeddingRequest {
            version: PROTOCOL_VERSION,
            image,
        };
        let plaintext = request.encode().map_err(|_| Error::Protocol)?;
        let (sealed, opener) = self
            .consumer
            .seal_to_enclave(&plaintext)
            .map_err(|_| Error::Authentication)?;
        if sealed.len() > MAX_REQUEST_BYTES {
            return Err(Error::Protocol);
        }
        Ok((
            sealed,
            PendingResult {
                opener,
                identity: self.identity.clone(),
            },
        ))
    }
}
// Called only after signature/chain, timestamp and channel commitment verification.
fn matches_release(
    releases: &[Release],
    identity: &WorkerIdentity,
    pcrs: [Option<&[u8]>; 3],
) -> bool {
    releases.iter().any(|release| {
        release.worker_sha384 == identity.executable_sha384
            && [&release.pcr0, &release.pcr1, &release.pcr2]
                .iter()
                .zip(pcrs)
                .all(|(expected, actual)| {
                    actual.is_some_and(|actual| hex::encode(actual) == **expected)
                })
    })
}
struct PendingResult {
    opener: ResponseOpener,
    identity: WorkerIdentity,
}
impl PendingResult {
    fn open(self, ciphertext: &[u8]) -> Result<EmbeddingResult, Error> {
        if ciphertext.len() > MAX_RESPONSE_BYTES {
            return Err(Error::Protocol);
        }
        let plaintext = self
            .opener
            .open_from_enclave(ciphertext)
            .map_err(|_| Error::Authentication)?;
        let result = EmbeddingResult::decode(&plaintext).map_err(|_| Error::Protocol)?;
        if let EmbeddingResult::Success { embedding } = &result
            && embedding.worker != self.identity
        {
            return Err(Error::Attestation);
        }
        Ok(result)
    }
}

pub enum Frame {
    Text(String),
    Binary(Vec<u8>),
}
/// A bounded transport. Dropping it must close the socket and release its resources.
#[allow(async_fn_in_trait)]
pub trait Transport {
    async fn send(&mut self, frame: Frame, timeout: Duration) -> Result<(), Error>;
    async fn receive(&mut self, timeout: Duration) -> Result<Frame, Error>;
    async fn close(&mut self);
}

/// Opens sessions whose enclave assignment has been verified before they are returned.
pub struct EnrollmentClient {
    config: Config,
}
impl EnrollmentClient {
    pub fn new(config: Config) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self { config })
    }

    async fn connect_transport<T: Transport>(
        &self,
        mut socket: T,
    ) -> Result<EnrollmentSession<T>, Error> {
        let result = async {
            let request = serde_json::to_string(&ClientMessage::AssignmentRequest)
                .map_err(|_| Error::Protocol)?;
            socket
                .send(Frame::Text(request), Duration::from_secs(5))
                .await?;
            let HostMessage::Assignment(assignment) =
                host_message(socket.receive(Duration::from_secs(10)).await?)?;
            VerifiedAssignment::verify(&self.config, &assignment)
        }
        .await;
        match result {
            Ok(assignment) => Ok(EnrollmentSession { socket, assignment }),
            Err(error) => {
                socket.close().await;
                Err(error)
            }
        }
    }
}

/// Owns one socket and the verified assignment received on that socket, as in Flamingo.
pub struct EnrollmentSession<T: Transport> {
    socket: T,
    assignment: VerifiedAssignment,
}
impl<T: Transport> EnrollmentSession<T> {
    pub fn assignment(&self) -> &VerifiedAssignment {
        &self.assignment
    }

    /// Consumes the session: one encrypted extraction, followed by socket cleanup on any result.
    pub async fn extract(mut self, image: Vec<u8>) -> Result<EmbeddingResult, Error> {
        let result = async {
            let (request, pending) = self.assignment.seal(image)?;
            self.socket
                .send(Frame::Binary(request), Duration::from_secs(10))
                .await?;
            match self.socket.receive(Duration::from_secs(40)).await? {
                Frame::Binary(response) => pending.open(&response),
                frame => {
                    host_message(frame)?;
                    Err(Error::Protocol)
                }
            }
        }
        .await;
        self.socket.close().await;
        result
    }
}
fn host_message(frame: Frame) -> Result<HostMessage, Error> {
    let Frame::Text(text) = frame else {
        return Err(Error::Protocol);
    };
    if text.len() > MAX_CONTROL_BYTES {
        return Err(Error::Protocol);
    }
    if let Ok(message) = serde_json::from_str::<HostMessage>(&text) {
        return Ok(message);
    }
    Err(serde_json::from_str::<ErrorEnvelope>(&text)
        .map_or(Error::Protocol, |envelope| Error::Host(envelope.error.code)))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        Config {
            endpoint: "wss://example.com/v1/embeddings".into(),
            releases: vec![Release {
                pcr0: "1".repeat(96),
                pcr1: "2".repeat(96),
                pcr2: "3".repeat(96),
                worker_sha384: "4".repeat(96),
            }],
        }
    }
    #[test]
    fn rejects_missing_zero_and_malformed_measurements_and_insecure_remote() {
        assert!(config().validate().is_ok());
        let mut prefixed = config();
        prefixed.endpoint = "wss://example.com/proxy/enrollment/v1/embeddings".into();
        assert!(prefixed.validate().is_ok());
        let mut c = config();
        c.releases.clear();
        assert!(c.validate().is_err());
        let mut c = config();
        c.releases[0].pcr0 = "0".repeat(96);
        assert!(c.validate().is_err());
        let mut c = config();
        c.releases[0].worker_sha384 = "x".repeat(96);
        assert!(c.validate().is_err());
        let mut c = config();
        c.endpoint = "ws://example.com/v1/embeddings".into();
        assert!(c.validate().is_err());
    }
    #[test]
    fn authenticated_worker_and_measurements_must_belong_to_the_same_release() {
        let mut config = config();
        let first = config.releases[0].clone();
        let second = Release {
            pcr0: "5".repeat(96),
            pcr1: "6".repeat(96),
            pcr2: "7".repeat(96),
            worker_sha384: "8".repeat(96),
        };
        config.releases.push(second.clone());
        let mut identity = WorkerIdentity {
            profile: PROFILE.into(),
            executable_sha384: first.worker_sha384.clone(),
        };
        let pcr0 = hex::decode(&first.pcr0).unwrap();
        let pcr1 = hex::decode(&first.pcr1).unwrap();
        let pcr2 = hex::decode(&first.pcr2).unwrap();
        let pcrs = [
            Some(pcr0.as_slice()),
            Some(pcr1.as_slice()),
            Some(pcr2.as_slice()),
        ];
        assert!(matches_release(&config.releases, &identity, pcrs));
        identity.executable_sha384 = second.worker_sha384;
        assert!(!matches_release(&config.releases, &identity, pcrs));
        identity.executable_sha384 = first.worker_sha384;
        let other_pcr = hex::decode(&second.pcr1).unwrap();
        assert!(!matches_release(
            &config.releases,
            &identity,
            [pcrs[0], Some(&other_pcr), pcrs[2]]
        ));
        assert!(!matches_release(
            &config.releases,
            &identity,
            [pcrs[0], None, pcrs[2]]
        ));
    }
}
