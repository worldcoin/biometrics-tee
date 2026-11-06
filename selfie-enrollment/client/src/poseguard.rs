//! Separate shadow evaluation: authenticated PoseGuard results do not gate vanilla enrollment.
use crate::{Error, Frame, Transport, host_message};
use pontifex::ChannelConsumer;
use selfie_enrollment_api_types::{MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
use selfie_enrollment_sealed_types::poseguard::{
    Action, MAX_EXCHANGES, Reply, Request, SESSION_TTL_SECS, VERSION,
};
pub use selfie_enrollment_sealed_types::poseguard::{Outcome, PROFILE, PoseTarget, Rejection};
use std::time::Duration;
use web_time::Instant;
use zeroize::{Zeroize, Zeroizing};

/// One bounded interactive evaluation on its own attested connection.
pub struct PoseGuardSession<T: Transport> {
    socket: Option<T>,
    consumer: ChannelConsumer,
    auth_key: Zeroizing<[u8; 32]>,
    reply: Reply,
    deadline: Instant,
}
impl<T: Transport> PoseGuardSession<T> {
    pub(crate) async fn begin(mut socket: T, consumer: ChannelConsumer) -> Result<Self, Error> {
        let deadline = Instant::now() + Duration::from_secs(SESSION_TTL_SECS);
        let result = async {
            let auth_key = random_secret()?;
            let request = Request {
                version: VERSION,
                nonce: *random_secret()?,
                action: Action::Begin {
                    auth_key: *auth_key,
                },
            };
            let reply = exchange(&mut socket, &consumer, &auth_key, &request).await?;
            if reply.next_sequence != 1
                || !matches!(
                    reply.outcome,
                    Outcome::Capture {
                        target: None,
                        challenge_index: 0,
                        sequence_attempt: 1,
                        retry: None
                    }
                )
            {
                return Err(Error::Protocol);
            }
            Ok((auth_key, reply))
        }
        .await;
        match result {
            Ok((auth_key, reply)) => Ok(Self {
                socket: Some(socket),
                consumer,
                auth_key,
                reply,
                deadline,
            }),
            Err(error) => {
                socket.close().await;
                Err(error)
            }
        }
    }
    pub fn current(&self) -> &Outcome {
        &self.reply.outcome
    }
    pub async fn submit(&mut self, image: Vec<u8>) -> Result<Outcome, Error> {
        let action = Action::Submit {
            session_id: self.reply.session_id,
            sequence: self.reply.next_sequence,
            image,
        };
        self.advance(action).await
    }
    pub async fn cancel(&mut self) -> Result<Outcome, Error> {
        let action = Action::Cancel {
            session_id: self.reply.session_id,
            sequence: self.reply.next_sequence,
        };
        self.advance(action).await
    }
    async fn advance(&mut self, action: Action) -> Result<Outcome, Error> {
        let result = async {
            if Instant::now() >= self.deadline {
                return Err(Error::Timeout);
            }
            if self.reply.outcome.is_complete() || self.reply.next_sequence >= MAX_EXCHANGES {
                return Err(Error::Protocol);
            }
            let request = Request {
                version: VERSION,
                nonce: *random_secret()?,
                action,
            };
            let socket = self.socket.as_mut().ok_or(Error::Protocol)?;
            let reply = exchange(socket, &self.consumer, &self.auth_key, &request).await?;
            if Instant::now() >= self.deadline {
                return Err(Error::Timeout);
            }
            if reply.session_id != self.reply.session_id
                || reply.next_sequence != self.reply.next_sequence + 1
            {
                return Err(Error::Protocol);
            }
            if matches!(request.action, Action::Cancel { .. })
                && !matches!(
                    reply.outcome,
                    Outcome::Complete {
                        passed: false,
                        reason: Some(Rejection::Cancelled)
                    }
                )
            {
                return Err(Error::Protocol);
            }
            self.reply = reply;
            Ok(self.reply.outcome.clone())
        }
        .await;
        if (result.is_err() || self.reply.outcome.is_complete())
            && let Some(mut socket) = self.socket.take()
        {
            self.auth_key.zeroize();
            self.reply.session_id.zeroize();
            self.reply.nonce.zeroize();
            socket.close().await;
        }
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
    if sealed.len() > MAX_REQUEST_BYTES {
        return Err(Error::Protocol);
    }
    socket
        .send(Frame::Binary(sealed), Duration::from_secs(10))
        .await?;
    let bytes = match socket.receive(Duration::from_secs(40)).await? {
        Frame::Binary(bytes) => bytes,
        frame => {
            host_message(frame)?;
            return Err(Error::Protocol);
        }
    };
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(Error::Protocol);
    }
    let plain = opener
        .open_from_enclave(&bytes)
        .map_err(|_| Error::Authentication)?;
    Reply::decode_authenticated(&plain, key, &request.nonce).map_err(|_| Error::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pontifex::{ChannelDomain, ChannelEnclave};
    use selfie_enrollment_api_types::CHANNEL_DOMAIN;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Clone, Copy)]
    enum Fault {
        None,
        WrongNonce,
        WrongSession,
        WrongSequence,
        WrongMac,
    }
    struct FakeTransport {
        enclave: ChannelEnclave,
        key: Option<[u8; 32]>,
        response: Option<Vec<u8>>,
        calls: usize,
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
            self.calls += 1;
            let (sequence, outcome) = match &request.action {
                Action::Begin { auth_key } => {
                    self.key = Some(*auth_key);
                    (
                        1,
                        Outcome::Capture {
                            target: None,
                            challenge_index: 0,
                            sequence_attempt: 1,
                            retry: None,
                        },
                    )
                }
                Action::Submit { sequence, .. } => (
                    *sequence + 1,
                    Outcome::Complete {
                        passed: true,
                        reason: None,
                    },
                ),
                Action::Cancel { sequence, .. } => (
                    *sequence + 1,
                    Outcome::Complete {
                        passed: false,
                        reason: Some(Rejection::Cancelled),
                    },
                ),
            };
            let mut reply = Reply {
                nonce: request.nonce,
                session_id: [8; 32],
                next_sequence: sequence,
                outcome,
            };
            let mut key = self.key.unwrap();
            if self.calls > 1 {
                match self.fault {
                    Fault::None => {}
                    Fault::WrongNonce => reply.nonce = [7; 32],
                    Fault::WrongSession => reply.session_id = [7; 32],
                    Fault::WrongSequence => reply.next_sequence += 1,
                    Fault::WrongMac => key = [7; 32],
                }
            }
            self.response = Some(
                sealer
                    .seal(&reply.encode_authenticated(&key).unwrap())
                    .unwrap(),
            );
            Ok(())
        }
        async fn receive(&mut self, _: Duration) -> Result<Frame, Error> {
            Ok(Frame::Binary(self.response.take().unwrap()))
        }
        async fn close(&mut self) {
            self.closed.fetch_add(1, Ordering::SeqCst);
        }
    }
    async fn session(fault: Fault) -> (PoseGuardSession<FakeTransport>, Arc<AtomicUsize>) {
        let enclave = ChannelEnclave::generate(ChannelDomain::new(CHANNEL_DOMAIN)).unwrap();
        let consumer = ChannelConsumer::from_unverified_public_key(
            ChannelDomain::new(CHANNEL_DOMAIN),
            &enclave.public_key(),
        )
        .unwrap();
        let closed = Arc::new(AtomicUsize::new(0));
        let socket = FakeTransport {
            enclave,
            key: None,
            response: None,
            calls: 0,
            closed: closed.clone(),
            fault,
        };
        (
            PoseGuardSession::begin(socket, consumer).await.unwrap(),
            closed,
        )
    }
    #[tokio::test]
    async fn completed_evaluation_closes_and_cannot_submit_again() {
        let (mut session, closed) = session(Fault::None).await;
        assert!(matches!(
            session.current(),
            Outcome::Capture { target: None, .. }
        ));
        assert_eq!(
            session.submit(vec![1]).await.unwrap(),
            Outcome::Complete {
                passed: true,
                reason: None
            }
        );
        assert_eq!(closed.load(Ordering::SeqCst), 1);
        assert!(session.submit(vec![1]).await.is_err());
        assert_eq!(closed.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn authenticated_reply_must_match_session_request_and_sequence() {
        for fault in [
            Fault::WrongNonce,
            Fault::WrongSession,
            Fault::WrongSequence,
            Fault::WrongMac,
        ] {
            let (mut session, closed) = session(fault).await;
            assert!(session.submit(vec![1]).await.is_err());
            assert_eq!(closed.load(Ordering::SeqCst), 1);
            assert!(session.submit(vec![1]).await.is_err());
        }
    }
    #[tokio::test]
    async fn cancellation_and_invalid_images_close_the_socket() {
        let (mut session, closed) = session(Fault::None).await;
        assert_eq!(
            session.cancel().await.unwrap(),
            Outcome::Complete {
                passed: false,
                reason: Some(Rejection::Cancelled)
            }
        );
        assert_eq!(closed.load(Ordering::SeqCst), 1);
        let (mut session, closed) = self::session(Fault::None).await;
        assert!(session.submit(Vec::new()).await.is_err());
        assert_eq!(closed.load(Ordering::SeqCst), 1);
    }
}
