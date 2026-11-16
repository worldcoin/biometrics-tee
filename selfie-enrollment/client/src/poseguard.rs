//! A verified session issues targets before accepting one complete capture batch.
use crate::{Error, Frame, Transport, host_message};
use pontifex::ChannelConsumer;
use selfie_enrollment_api_types::{
    MAX_BATCH_REQUEST_BYTES, MAX_CHALLENGE_RESPONSE_BYTES, MAX_RESPONSE_BYTES, WORKER_TIMEOUT_SECS,
};
pub use selfie_enrollment_sealed_types::poseguard::{
    CaptureBatch, Challenge, ChallengeImage, PoseTarget,
};
use selfie_enrollment_sealed_types::{
    EnrollmentResult,
    poseguard::{Action, Outcome, Reply, Request, VERSION},
};
use std::time::Duration;
use web_time::Instant;
use zeroize::Zeroizing;

pub struct PoseGuardSession<T: Transport> {
    socket: T,
    consumer: ChannelConsumer,
    auth_key: Zeroizing<[u8; 32]>,
    challenge: Challenge,
    deadline: Instant,
}
impl<T: Transport> PoseGuardSession<T> {
    pub(crate) async fn begin(
        mut socket: T,
        consumer: ChannelConsumer,
        sub: String,
        custody_public_key: [u8; 32],
    ) -> Result<Self, Error> {
        let started = Instant::now();
        let result = async {
            let key = random_secret()?;
            let request = Request {
                version: VERSION,
                nonce: *random_secret()?,
                action: Action::Begin {
                    sub,
                    custody_public_key,
                    auth_key: *key,
                },
            };
            let mut reply = exchange(&mut socket, &consumer, &key, &request).await?;
            let Outcome::Challenge { challenge } =
                std::mem::replace(&mut reply.outcome, Outcome::Cancelled)
            else {
                return Err(Error::Protocol);
            };
            let deadline = started + Duration::from_millis(challenge.expires_in_ms);
            if Instant::now() >= deadline {
                return Err(Error::Timeout);
            }
            Ok((key, challenge, deadline))
        }
        .await;
        match result {
            Ok((auth_key, challenge, deadline)) => Ok(Self {
                socket,
                consumer,
                auth_key,
                challenge,
                deadline,
            }),
            Err(error) => {
                socket.close().await;
                Err(error)
            }
        }
    }
    pub fn challenge(&self) -> &Challenge {
        &self.challenge
    }
    pub async fn enroll(mut self, capture: CaptureBatch) -> Result<EnrollmentResult, Error> {
        let result = async {
            if Instant::now() >= self.deadline {
                return Err(Error::Timeout);
            }
            let request = Request {
                version: VERSION,
                nonce: *random_secret()?,
                action: Action::Submit {
                    session_id: self.challenge.session_id,
                    capture,
                },
            };
            let mut reply =
                exchange(&mut self.socket, &self.consumer, &self.auth_key, &request).await?;
            if reply.session_id != self.challenge.session_id {
                return Err(Error::Authentication);
            }
            match std::mem::replace(&mut reply.outcome, Outcome::Cancelled) {
                Outcome::Enrollment { result } => Ok(result),
                _ => Err(Error::Protocol),
            }
        }
        .await;
        self.socket.close().await;
        result
    }
    pub async fn cancel(mut self) -> Result<(), Error> {
        let result = async {
            let request = Request {
                version: VERSION,
                nonce: *random_secret()?,
                action: Action::Cancel {
                    session_id: self.challenge.session_id,
                },
            };
            let reply =
                exchange(&mut self.socket, &self.consumer, &self.auth_key, &request).await?;
            if reply.session_id != self.challenge.session_id
                || !matches!(reply.outcome, Outcome::Cancelled)
            {
                return Err(Error::Authentication);
            }
            Ok(())
        }
        .await;
        self.socket.close().await;
        result
    }
}
fn random_secret() -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut secret = Zeroizing::new([0; 32]);
    getrandom::getrandom(&mut *secret).map_err(|_| Error::Authentication)?;
    if *secret == [0; 32] {
        return Err(Error::Authentication);
    }
    Ok(secret)
}
async fn exchange<T: Transport>(
    socket: &mut T,
    consumer: &ChannelConsumer,
    key: &[u8; 32],
    request: &Request,
) -> Result<Reply, Error> {
    let plain = request.encode().map_err(|_| Error::Protocol)?;
    let (sealed, opener) = consumer
        .seal_to_enclave(&plain)
        .map_err(|_| Error::Authentication)?;
    if sealed.len() > MAX_BATCH_REQUEST_BYTES {
        return Err(Error::Protocol);
    }
    socket
        .send(Frame::Binary(sealed), Duration::from_secs(10))
        .await?;
    let response = match socket
        .receive(Duration::from_secs(WORKER_TIMEOUT_SECS + 10))
        .await?
    {
        Frame::Binary(bytes) => bytes,
        frame => {
            host_message(frame)?;
            return Err(Error::Protocol);
        }
    };
    let response_limit = if matches!(request.action, Action::Submit { .. }) {
        MAX_RESPONSE_BYTES
    } else {
        MAX_CHALLENGE_RESPONSE_BYTES
    };
    if response.len() > response_limit {
        return Err(Error::Protocol);
    }
    let plain = opener
        .open_from_enclave(&response)
        .map_err(|_| Error::Authentication)?;
    Reply::decode_authenticated(&plain, key, &request.nonce).map_err(|_| Error::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pontifex::{ChannelDomain, ChannelEnclave};
    use selfie_enrollment_api_types::CHANNEL_DOMAIN;
    use selfie_enrollment_sealed_types::{ChallengeFailure, Failure};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Clone, Copy)]
    enum Fault {
        None,
        WrongMac,
        WrongNonce,
        WrongSession,
        WrongPhase,
    }
    struct FakeTransport {
        enclave: ChannelEnclave,
        key: [u8; 32],
        response: Option<Vec<u8>>,
        calls: Arc<AtomicUsize>,
        closed: Arc<AtomicUsize>,
        fault: Fault,
    }
    impl Transport for FakeTransport {
        async fn send(&mut self, frame: Frame, _: Duration) -> Result<(), Error> {
            let Frame::Binary(bytes) = frame else {
                return Err(Error::Protocol);
            };
            let (plain, sealer) = self.enclave.open(&bytes).unwrap();
            let request = Request::decode(&plain).unwrap();
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let outcome = match &request.action {
                Action::Begin {
                    auth_key,
                    sub,
                    custody_public_key,
                } => {
                    assert_eq!(sub, "0x1f");
                    assert_eq!(*custody_public_key, [8; 32]);
                    self.key = *auth_key;
                    Outcome::Challenge {
                        challenge: Challenge {
                            session_id: [7; 32],
                            targets: [PoseTarget { pitch: 15, yaw: 25 }; 3],
                            expires_in_ms: 90_000,
                        },
                    }
                }
                Action::Submit {
                    session_id,
                    capture,
                } => {
                    assert_eq!(*session_id, [7; 32]);
                    assert_eq!(capture.central_png, b"\x89PNG\r\n\x1a\ncentral");
                    for (i, image) in capture.challenges.iter().enumerate() {
                        assert_eq!(image.0, vec![i as u8 + 1]);
                    }
                    Outcome::Enrollment {
                        result: EnrollmentResult::Failed {
                            reason: Failure::Challenge {
                                index: 2,
                                reason: ChallengeFailure::PoseMismatch,
                            },
                        },
                    }
                }
                Action::Cancel { session_id } => {
                    assert_eq!(*session_id, [7; 32]);
                    Outcome::Cancelled
                }
            };
            let mut reply = Reply {
                nonce: request.nonce,
                session_id: [7; 32],
                outcome,
            };
            if matches!(self.fault, Fault::WrongNonce) {
                reply.nonce = [99; 32];
            }
            if call == 1 && matches!(self.fault, Fault::WrongSession) {
                reply.session_id = [99; 32];
            }
            if call == 1 && matches!(self.fault, Fault::WrongPhase) {
                reply.outcome = Outcome::Cancelled;
            }
            let key = if matches!(self.fault, Fault::WrongMac) {
                [99; 32]
            } else {
                self.key
            };
            self.response = Some(
                sealer
                    .seal(&reply.encode_authenticated(&key).unwrap())
                    .unwrap(),
            );
            Ok(())
        }
        async fn receive(&mut self, _: Duration) -> Result<Frame, Error> {
            Ok(Frame::Binary(self.response.take().ok_or(Error::Protocol)?))
        }
        async fn close(&mut self) {
            self.closed.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn transport(
        fault: Fault,
    ) -> (
        FakeTransport,
        ChannelConsumer,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
    ) {
        let enclave = ChannelEnclave::generate(ChannelDomain::new(CHANNEL_DOMAIN)).unwrap();
        let consumer = ChannelConsumer::from_unverified_public_key(
            ChannelDomain::new(CHANNEL_DOMAIN),
            &enclave.public_key(),
        )
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        (
            FakeTransport {
                enclave,
                key: [0; 32],
                response: None,
                calls: calls.clone(),
                closed: closed.clone(),
                fault,
            },
            consumer,
            calls,
            closed,
        )
    }
    fn batch() -> CaptureBatch {
        CaptureBatch {
            central_png: b"\x89PNG\r\n\x1a\ncentral".to_vec(),
            challenges: std::array::from_fn(|i| ChallengeImage(vec![i as u8 + 1])),
        }
    }

    #[tokio::test]
    async fn begins_before_capture_and_submits_all_four_images_once() {
        let (socket, consumer, calls, closed) = transport(Fault::None);
        let session = PoseGuardSession::begin(socket, consumer, "0x1f".into(), [8; 32])
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(closed.load(Ordering::SeqCst), 0);
        assert_eq!(session.challenge().targets.len(), 3);
        let result = session.enroll(batch()).await.unwrap();
        assert!(matches!(
            result,
            EnrollmentResult::Failed {
                reason: Failure::Challenge {
                    index: 2,
                    reason: ChallengeFailure::PoseMismatch
                }
            }
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(closed.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn unauthenticated_or_replayed_targets_are_rejected_and_closed() {
        for fault in [Fault::WrongMac, Fault::WrongNonce] {
            let (socket, consumer, calls, closed) = transport(fault);
            assert!(matches!(
                PoseGuardSession::begin(socket, consumer, "0x1f".into(), [8; 32]).await,
                Err(Error::Authentication)
            ));
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(closed.load(Ordering::SeqCst), 1);
        }
    }
    #[tokio::test]
    async fn wrong_terminal_session_or_phase_is_rejected() {
        for fault in [Fault::WrongSession, Fault::WrongPhase] {
            let (socket, consumer, _, closed) = transport(fault);
            let session = PoseGuardSession::begin(socket, consumer, "0x1f".into(), [8; 32])
                .await
                .unwrap();
            assert!(session.enroll(batch()).await.is_err());
            assert_eq!(closed.load(Ordering::SeqCst), 1);
        }
    }
    #[tokio::test]
    async fn cancellation_expiry_and_bad_capture_close_without_submission() {
        for mode in 0..3 {
            let (socket, consumer, calls, closed) = transport(Fault::None);
            let mut session = PoseGuardSession::begin(socket, consumer, "0x1f".into(), [8; 32])
                .await
                .unwrap();
            match mode {
                0 => {
                    session.cancel().await.unwrap();
                    assert_eq!(calls.load(Ordering::SeqCst), 2);
                }
                1 => {
                    session.deadline = Instant::now();
                    assert!(matches!(session.enroll(batch()).await, Err(Error::Timeout)));
                    assert_eq!(calls.load(Ordering::SeqCst), 1);
                }
                _ => {
                    let mut bad = batch();
                    bad.central_png = b"jpeg".to_vec();
                    assert!(matches!(session.enroll(bad).await, Err(Error::Protocol)));
                    assert_eq!(calls.load(Ordering::SeqCst), 1);
                }
            }
            assert_eq!(closed.load(Ordering::SeqCst), 1);
        }
    }
}
