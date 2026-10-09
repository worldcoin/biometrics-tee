//! Fail-closed enrollment client. Measurement and worker allowlists always come from the caller.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use pontifex::{
    ChannelConsumer, ChannelDomain, ResponseOpener,
    attestation::{PcrConfig, Verifier},
};
use selfie_enrollment_api_types::*;
use selfie_enrollment_sealed_types::{EmbeddingRequest, EmbeddingResult, WorkerIdentity};
use serde::{Deserialize, Serialize};
use std::{future::Future, time::Duration};
use zeroize::Zeroizing;

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
    pub audience: String,
    pub releases: Vec<Release>,
}
impl Config {
    pub fn validate(&self) -> Result<(), Error> {
        self.verifier()?;
        if self.audience.is_empty() || self.audience.len() > 256 {
            return Err(Error::Config);
        }
        let url = url::Url::parse(&self.endpoint).map_err(|_| Error::Config)?;
        let local = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
        if (url.scheme() != "wss" && !(url.scheme() == "ws" && local))
            || url.path() != "/v1/embeddings"
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
    #[error("test admission failed")]
    Admission,
}

/// Holds the verified boot key and single-use nonce together.
pub struct VerifiedAssignment {
    consumer: ChannelConsumer,
    nonce: [u8; 32],
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
        let matches_release = config.releases.iter().any(|r| {
            r.worker_sha384 == identity.executable_sha384
                && [(&r.pcr0, 0), (&r.pcr1, 1), (&r.pcr2, 2)]
                    .iter()
                    .all(|(expected, index)| {
                        verified
                            .document()
                            .pcrs
                            .get(index)
                            .is_some_and(|actual| hex::encode(actual) == **expected)
                    })
        });
        if !matches_release {
            return Err(Error::Attestation);
        }
        Ok(Self {
            consumer,
            nonce: assignment.nonce,
            identity,
        })
    }
    pub fn seal(self, image: Vec<u8>) -> Result<(Vec<u8>, PendingResult), Error> {
        let request = EmbeddingRequest {
            version: PROTOCOL_VERSION,
            nonce: self.nonce,
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
                identity: self.identity,
            },
        ))
    }
}
pub struct PendingResult {
    opener: ResponseOpener,
    identity: WorkerIdentity,
}
impl PendingResult {
    pub fn open(self, ciphertext: &[u8]) -> Result<EmbeddingResult, Error> {
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
/// A bounded transport. Dropping it must close the socket and release listeners/resources.
#[allow(async_fn_in_trait)]
pub trait Transport {
    async fn send(&mut self, frame: Frame, timeout: Duration) -> Result<(), Error>;
    async fn receive(&mut self, timeout: Duration) -> Result<Frame, Error>;
}

/// Shared browser/native session sequencing. The issuer signs a server nonce for this socket;
/// it receives no biometric data. A captured ticket cannot be reused on another connection.
pub async fn exchange<T, F, Fut>(
    socket: &mut T,
    config: &Config,
    image: Vec<u8>,
    issuer: F,
) -> Result<EmbeddingResult, Error>
where
    T: Transport,
    F: FnOnce(AdmissionChallenge) -> Fut,
    Fut: Future<Output = Result<AdmissionTicket, Error>>,
{
    config.validate()?;
    let image = Zeroizing::new(image);
    if image.is_empty() || image.len() > MAX_IMAGE_BYTES {
        return Err(Error::Protocol);
    }
    let challenge = match server_message(socket.receive(Duration::from_secs(10)).await?)? {
        ServerMessage::Admission(c) if c.audience == config.audience => c,
        _ => return Err(Error::Admission),
    };
    let ticket = issuer(challenge).await?;
    let encoded = serde_json::to_string(&ticket).map_err(|_| Error::Protocol)?;
    if encoded.len() > MAX_TICKET_BYTES {
        return Err(Error::Admission);
    }
    socket
        .send(Frame::Text(encoded), Duration::from_secs(5))
        .await?;
    let assignment = match server_message(socket.receive(Duration::from_secs(10)).await?)? {
        ServerMessage::Assignment(a) => a,
        _ => return Err(Error::Protocol),
    };
    let verified = VerifiedAssignment::verify(config, &assignment)?;
    let (request, pending) = verified.seal(image.to_vec())?;
    socket
        .send(Frame::Binary(request), Duration::from_secs(10))
        .await?;
    match socket.receive(Duration::from_secs(40)).await? {
        Frame::Binary(response) => pending.open(&response),
        frame => {
            server_message(frame)?;
            Err(Error::Protocol)
        }
    }
}
fn server_message(frame: Frame) -> Result<ServerMessage, Error> {
    let Frame::Text(text) = frame else {
        return Err(Error::Protocol);
    };
    if text.len() > MAX_CONTROL_BYTES {
        return Err(Error::Protocol);
    }
    match serde_json::from_str(&text).map_err(|_| Error::Protocol)? {
        ServerMessage::Error { code } => Err(Error::Host(code)),
        message => Ok(message),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        Config {
            endpoint: "wss://example.com/v1/embeddings".into(),
            audience: "stage".into(),
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
}
