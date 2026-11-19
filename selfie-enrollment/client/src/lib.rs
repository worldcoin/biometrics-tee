//! Fail-closed enrollment client. Measurement allowlists always come from the caller.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::future::{Either, select};
use pontifex::{
    ChannelConsumer, ChannelDomain, ResponseOpener,
    attestation::{PcrConfig, VerifiedAttestation, Verifier},
};
use rand::RngCore;
use selfie_enrollment_api_types::*;
pub use selfie_enrollment_sealed_types::PoseGuardTarget;
use selfie_enrollment_sealed_types::{
    EmbeddingRequest, EmbeddingResult, EnrollmentOperation, EnrollmentRequest, EnrollmentResult,
    GeneratePoseGuardTargetsRequest, PoseGuardCapture, PoseGuardChallenge,
    PoseGuardEnrollmentRequest, PoseGuardTargetsResult,
};
use serde::{Deserialize, Serialize};
use std::{pin::pin, time::Duration};
use web_time::Instant;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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
    #[error("enclave attestation rejected")]
    Attestation,
    #[error("invalid enrollment message")]
    Protocol,
    #[error("enrollment transport failed")]
    Transport,
    #[error("enrollment timed out or was cancelled")]
    Timeout,
    #[error("enrollment response authentication failed")]
    Authentication,
    #[error("PoseGuard capture failed")]
    Capture,
    #[error("enrollment host: {0}")]
    Host(ErrorCode),
}

/// Holds the verified attestation and boot-scoped channel key.
pub struct VerifiedAssignment {
    attestation: VerifiedAttestation,
    consumer: ChannelConsumer,
    verifier: Verifier,
    commitment: [u8; 32],
}
impl VerifiedAssignment {
    pub fn verify(config: &Config, assignment: &Assignment) -> Result<Self, Error> {
        config.validate()?;
        Self::verify_with(config.verifier()?, assignment)
    }

    /// Verifies `assignment` under `verifier`; tests substitute a verifier rooted in a test CA.
    fn verify_with(verifier: Verifier, assignment: &Assignment) -> Result<Self, Error> {
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
            &verifier,
            &doc,
            &public_key,
        )
        .map_err(|_| Error::Attestation)?;
        Ok(Self {
            attestation: verified,
            consumer,
            verifier,
            commitment: ChannelDomain::new(CHANNEL_DOMAIN).public_key_commitment(&public_key),
        })
    }
    pub fn attestation(&self) -> &VerifiedAttestation {
        &self.attestation
    }
    pub fn consumer(&self) -> &ChannelConsumer {
        &self.consumer
    }
    fn seal(&self, image: Vec<u8>) -> Result<(Vec<u8>, PendingResult), Error> {
        let request = EmbeddingRequest {
            version: PROTOCOL_VERSION,
            image,
        };
        self.seal_plaintext(&request.encode().map_err(|_| Error::Protocol)?)
    }
    fn seal_enrollment(
        &self,
        image: Vec<u8>,
        sub: String,
        custody_public_key: [u8; 32],
    ) -> Result<(Vec<u8>, PendingResult), Error> {
        let request = EnrollmentRequest {
            version: ENROLLMENT_PROTOCOL_VERSION,
            image,
            sub,
            custody_public_key: custody_public_key.to_vec(),
        };
        self.seal_plaintext(&request.encode().map_err(|_| Error::Protocol)?)
    }
    fn seal_plaintext(&self, plaintext: &[u8]) -> Result<(Vec<u8>, PendingResult), Error> {
        let (sealed, opener) = self
            .consumer
            .seal_to_enclave(plaintext)
            .map_err(|_| Error::Authentication)?;
        if sealed.len() > MAX_POSEGUARD_REQUEST_BYTES {
            return Err(Error::Protocol);
        }
        Ok((sealed, PendingResult { opener }))
    }
}
struct PendingResult {
    opener: ResponseOpener,
}
impl PendingResult {
    fn open(self, ciphertext: &[u8]) -> Result<EmbeddingResult, Error> {
        EmbeddingResult::decode(&self.open_plaintext(ciphertext)?).map_err(|_| Error::Protocol)
    }
    fn open_enrollment(self, ciphertext: &[u8]) -> Result<EnrollmentResult, Error> {
        EnrollmentResult::decode(&self.open_plaintext(ciphertext)?).map_err(|_| Error::Protocol)
    }
    fn open_plaintext(self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        if ciphertext.len() > MAX_RESPONSE_BYTES {
            return Err(Error::Protocol);
        }
        self.opener
            .open_from_enclave(ciphertext)
            .map_err(|_| Error::Authentication)
    }
}

pub enum Frame {
    Text(String),
    Binary(Vec<u8>),
}
/// A bounded transport. Dropping it must close the socket and release its resources, and
/// dropping a pending `receive` must not consume a frame.
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
    pub async fn extract(self, image: Vec<u8>) -> Result<EmbeddingResult, Error> {
        let (request, pending) = self.assignment.seal(image)?;
        let response = self.round_trip(request).await?;
        pending.open(&response)
    }

    /// Consumes the session: one encrypted enrollment. On success the result carries the
    /// attested capture fields, the attestation header and the user's PCP, sealed to
    /// `custody_public_key`. The caller adds its v4 challenge and proof and submits.
    pub async fn enroll(
        self,
        image: Vec<u8>,
        sub: String,
        custody_public_key: [u8; 32],
    ) -> Result<EnrollmentResult, Error> {
        let (request, pending) = self
            .assignment
            .seal_enrollment(image, sub, custody_public_key)?;
        let response = self.round_trip(request).await?;
        pending.open_enrollment(&response)
    }

    /// Consumes the session for one PoseGuard attempt. Once the enclave issues authenticated
    /// targets, `capture` receives them and returns the central image and one capture per
    /// target; the client pairs each capture with its target and submits them on this socket.
    /// Capture ends early when the challenge expires, the socket fails or the host sends a
    /// frame. The socket closes on every result.
    pub async fn enroll_with_poseguard(
        mut self,
        sub: String,
        custody_public_key: [u8; 32],
        capture: impl AsyncFnOnce(PoseGuardPrompt) -> Result<PoseGuardImages, Error>,
    ) -> Result<EnrollmentResult, Error> {
        let result = self
            .poseguard_attempt(sub, custody_public_key, capture)
            .await;
        self.socket.close().await;
        result
    }

    async fn poseguard_attempt(
        &mut self,
        sub: String,
        custody_public_key: [u8; 32],
        capture: impl AsyncFnOnce(PoseGuardPrompt) -> Result<PoseGuardImages, Error>,
    ) -> Result<EnrollmentResult, Error> {
        let deadline = Instant::now() + Duration::from_secs(POSEGUARD_CHALLENGE_TTL_SECS);
        let challenge = self.request_poseguard_challenge(deadline).await?;
        let prompt = PoseGuardPrompt {
            targets: challenge.targets,
            expires_at: challenge.expires_at,
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        let images = await_capture(&mut self.socket, capture(prompt), remaining).await?;
        if Instant::now() >= deadline {
            return Err(Error::Timeout);
        }
        let (central_png, captures) = images.into_request_parts();
        let input = PoseGuardEnrollmentRequest {
            version: ENROLLMENT_PROTOCOL_VERSION,
            operation: EnrollmentOperation::EnrollWithPoseGuard,
            central_png,
            captures,
            sub,
            custody_public_key: custody_public_key.to_vec(),
            challenge_token: challenge.challenge_token,
        };
        let (request, pending) = self
            .assignment
            .seal_plaintext(&input.encode().map_err(|_| Error::Protocol)?)?;
        drop(input);
        let response = self.exchange(request).await?;
        pending.open_enrollment(&response)
    }

    /// Requests a challenge bound to this request and the assigned enclave boot.
    async fn request_poseguard_challenge(
        &mut self,
        deadline: Instant,
    ) -> Result<PoseGuardChallenge, Error> {
        let mut nonce = [0; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Authentication)?;
        let input = GeneratePoseGuardTargetsRequest {
            version: ENROLLMENT_PROTOCOL_VERSION,
            operation: EnrollmentOperation::GeneratePoseGuardTargets,
            nonce,
        };
        let (request, pending) = self
            .assignment
            .seal_plaintext(&input.encode().map_err(|_| Error::Protocol)?)?;
        let response = self.exchange(request).await?;
        let result = PoseGuardTargetsResult::decode(&pending.open_plaintext(&response)?)
            .map_err(|_| Error::Protocol)?;
        let expected = result
            .challenge
            .attestation_nonce(&input, &self.assignment.commitment)
            .map_err(|_| Error::Protocol)?;
        // Channel response encryption alone does not authenticate its sender.
        let proof = self
            .assignment
            .verifier
            .verify_attestation_document(&result.attestation)
            .map_err(|_| Error::Attestation)?;
        if proof
            .document()
            .nonce
            .as_ref()
            .map(|nonce| nonce.as_slice())
            != Some(expected.as_slice())
        {
            return Err(Error::Authentication);
        }
        if Instant::now() >= deadline {
            return Err(Error::Timeout);
        }
        Ok(result.challenge.clone())
    }

    async fn round_trip(mut self, request: Vec<u8>) -> Result<Vec<u8>, Error> {
        let result = self.exchange(request).await;
        self.socket.close().await;
        result
    }

    async fn exchange(&mut self, request: Vec<u8>) -> Result<Vec<u8>, Error> {
        self.socket
            .send(Frame::Binary(request), Duration::from_secs(10))
            .await?;
        match self.socket.receive(Duration::from_secs(40)).await? {
            Frame::Binary(response) => Ok(response),
            frame => {
                host_message(frame)?;
                Err(Error::Protocol)
            }
        }
    }
}

/// Authenticated targets for one PoseGuard attempt, in capture order. `expires_at` is in Unix
/// seconds for display; the client and enclave enforce monotonic deadlines.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PoseGuardPrompt {
    pub targets: [PoseGuardTarget; POSEGUARD_CHALLENGE_COUNT],
    pub expires_at: u64,
}

/// The central image and one capture per target, in target order.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PoseGuardImages {
    pub central_png: Vec<u8>,
    pub captures: [Vec<u8>; POSEGUARD_CHALLENGE_COUNT],
}

impl PoseGuardImages {
    /// Moves the images into the request; the enclave pairs each capture with its stored target.
    fn into_request_parts(mut self) -> (Vec<u8>, [PoseGuardCapture; POSEGUARD_CHALLENGE_COUNT]) {
        let captures = std::array::from_fn(|index| PoseGuardCapture {
            image: std::mem::take(&mut self.captures[index]),
        });
        (std::mem::take(&mut self.central_png), captures)
    }
}

/// Runs `capture` while the session idles; a host frame, socket failure or expiry ends it first.
async fn await_capture<T: Transport>(
    socket: &mut T,
    capture: impl Future<Output = Result<PoseGuardImages, Error>>,
    remaining: Duration,
) -> Result<PoseGuardImages, Error> {
    let capture = pin!(capture);
    let interruption = pin!(socket.receive(remaining));
    match select(capture, interruption).await {
        Either::Left((images, _)) => images,
        Either::Right((frame, _)) => {
            host_message(frame?)?;
            Err(Error::Protocol)
        }
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
mod challenge_tests;
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
        c.releases[0].pcr1 = "x".repeat(96);
        assert!(c.validate().is_err());
        let mut c = config();
        c.endpoint = "ws://example.com/v1/embeddings".into();
        assert!(c.validate().is_err());
    }

    /// Yields one scripted `receive` result, then never resolves again.
    struct ScriptedTransport(Option<Result<Frame, Error>>);
    impl Transport for ScriptedTransport {
        async fn send(&mut self, _: Frame, _: Duration) -> Result<(), Error> {
            Ok(())
        }
        async fn receive(&mut self, _: Duration) -> Result<Frame, Error> {
            match self.0.take() {
                Some(result) => result,
                None => std::future::pending().await,
            }
        }
        async fn close(&mut self) {}
    }

    fn images() -> PoseGuardImages {
        PoseGuardImages {
            central_png: vec![0],
            captures: [vec![1], vec![2], vec![3]],
        }
    }

    fn wait(
        socket: &mut ScriptedTransport,
        capture: impl Future<Output = Result<PoseGuardImages, Error>>,
    ) -> Result<PoseGuardImages, Error> {
        use futures_util::FutureExt;
        await_capture(socket, capture, Duration::from_secs(1))
            .now_or_never()
            .expect("the capture or the socket is ready")
    }

    #[test]
    fn capture_completes_while_the_socket_idles() {
        let captured = wait(&mut ScriptedTransport(None), async { Ok(images()) }).unwrap();
        assert_eq!(captured.captures, [vec![1], vec![2], vec![3]]);
    }

    #[test]
    fn expiry_socket_failure_and_host_frames_end_capture() {
        let host_error = serde_json::to_string(&ErrorEnvelope::from(ErrorCode::Timeout)).unwrap();
        for (event, expected) in [
            (Err(Error::Timeout), "Timeout"),
            (Err(Error::Transport), "Transport"),
            (Ok(Frame::Text(host_error)), "Host(Timeout)"),
            (Ok(Frame::Binary(vec![1])), "Protocol"),
        ] {
            let error = wait(&mut ScriptedTransport(Some(event)), std::future::pending())
                .err()
                .expect("capture is interrupted");
            assert_eq!(format!("{error:?}"), expected);
        }
    }
}
