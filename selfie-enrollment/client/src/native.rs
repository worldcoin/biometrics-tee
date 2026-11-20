//! Native diagnostic transport; the browser uses the same exchange and verification code.
use crate::{Config, EnrollmentClient, EnrollmentSession, Error, Frame, Transport};
use futures_util::{SinkExt, StreamExt};
use selfie_enrollment_api_types::MAX_RESPONSE_BYTES;
use std::{sync::Arc, time::Duration};
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
    async fn close(&mut self) {
        let _ = tokio::time::timeout(Duration::from_secs(1), self.0.close(None)).await;
    }
}

impl EnrollmentClient {
    pub async fn connect(&self) -> Result<EnrollmentSession<NativeTransport>, Error> {
        self.connect_transport(NativeTransport::connect(&self.config).await?)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Release;
    use selfie_enrollment_api_types::MAX_POSEGUARD_REQUEST_BYTES;

    /// The frame limits bound only what the client receives, so a request can use the host's
    /// full PoseGuard limit while responses stay capped.
    #[tokio::test]
    async fn sends_full_size_poseguard_requests_and_bounds_responses() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}/v1/embeddings", listener.local_addr().unwrap());
        let host = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let limits = WebSocketConfig::default()
                .max_message_size(Some(MAX_POSEGUARD_REQUEST_BYTES))
                .max_frame_size(Some(MAX_POSEGUARD_REQUEST_BYTES));
            let mut socket = tokio_tungstenite::accept_async_with_config(stream, Some(limits))
                .await
                .unwrap();
            let Some(Ok(Message::Binary(request))) = socket.next().await else {
                panic!("the request must arrive as one binary message");
            };
            let oversized = vec![0; MAX_RESPONSE_BYTES + 1];
            let _ = socket.send(Message::Binary(oversized.into())).await;
            request.len()
        });
        let config = Config {
            endpoint,
            releases: vec![Release {
                pcr0: "1".repeat(96),
                pcr1: "2".repeat(96),
                pcr2: "3".repeat(96),
            }],
        };
        let mut transport = NativeTransport::connect(&config).await.unwrap();
        let request = vec![7; MAX_POSEGUARD_REQUEST_BYTES];
        transport
            .send(Frame::Binary(request), Duration::from_secs(10))
            .await
            .unwrap();
        let response = transport.receive(Duration::from_secs(10)).await;
        drop(transport);
        assert!(matches!(response, Err(Error::Transport)));
        assert_eq!(host.await.unwrap(), MAX_POSEGUARD_REQUEST_BYTES);
    }
}
