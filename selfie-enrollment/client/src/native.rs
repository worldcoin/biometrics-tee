//! Native diagnostic transport; the browser uses the same exchange and verification code.
use crate::{Config, Error, Frame, Transport};
use futures_util::{SinkExt, StreamExt};
use selfie_enrollment_api_types::{AdmissionChallenge, AdmissionTicket, MAX_RESPONSE_BYTES};
use selfie_enrollment_sealed_types::EmbeddingResult;
use std::{future::Future, sync::Arc, time::Duration};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream,
    tungstenite::{Message, protocol::WebSocketConfig},
};
type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
pub struct NativeTransport(Socket);
impl NativeTransport {
    pub async fn connect(config: &Config) -> Result<Self, Error> {
        config.validate()?;
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::Config)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let limits = WebSocketConfig::default()
            .max_message_size(Some(MAX_RESPONSE_BYTES))
            .max_frame_size(Some(MAX_RESPONSE_BYTES));
        let (socket, _) = tokio::time::timeout(
            Duration::from_secs(5),
            tokio_tungstenite::connect_async_tls_with_config(
                &config.endpoint,
                Some(limits),
                false,
                Some(Connector::Rustls(Arc::new(tls))),
            ),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::Transport)?;
        Ok(Self(socket))
    }
}
impl Transport for NativeTransport {
    async fn send(&mut self, frame: Frame, duration: Duration) -> Result<(), Error> {
        let message = match frame {
            Frame::Text(s) => Message::Text(s.into()),
            Frame::Binary(b) => Message::Binary(b.into()),
        };
        tokio::time::timeout(duration, self.0.send(message))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Transport)
    }
    async fn receive(&mut self, duration: Duration) -> Result<Frame, Error> {
        let deadline = tokio::time::Instant::now() + duration;
        loop {
            match tokio::time::timeout_at(deadline, self.0.next())
                .await
                .map_err(|_| Error::Timeout)?
            {
                Some(Ok(Message::Text(s))) => return Ok(Frame::Text(s.to_string())),
                Some(Ok(Message::Binary(b))) => return Ok(Frame::Binary(b.to_vec())),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                _ => return Err(Error::Transport),
            }
        }
    }
}
pub async fn extract<F, Fut>(
    config: &Config,
    image: Vec<u8>,
    issuer: F,
) -> Result<EmbeddingResult, Error>
where
    F: FnOnce(AdmissionChallenge) -> Fut,
    Fut: Future<Output = Result<AdmissionTicket, Error>>,
{
    let mut socket = NativeTransport::connect(config).await?;
    let result = tokio::time::timeout(
        Duration::from_secs(100),
        crate::exchange(&mut socket, config, image, issuer),
    )
    .await
    .map_err(|_| Error::Timeout)?;
    let _ = tokio::time::timeout(Duration::from_secs(1), socket.0.close(None)).await;
    result
}
