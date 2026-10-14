//! KMS HTTPS terminates inside the enclave.
//!
//! The parent can relay or drop bytes,
//! but cannot read private keys or choose the wrapping key. No endpoint, proxy,
//! credential environment or custom CA settings are loaded from the parent.

use aws_credential_types::provider::{self, ProvideCredentials, error::CredentialsError, future};
use aws_sdk_kms::{
    Client,
    config::{BehaviorVersion, Region},
};
use aws_smithy_runtime_api::client::{
    http::{HttpConnector, HttpConnectorFuture, SharedHttpConnector, http_client_fn},
    orchestrator::{HttpRequest, HttpResponse},
    result::ConnectorError,
};
use aws_smithy_types::body::SdkBody;
use di_migration_enclave_primitives::kms::{
    self as wire, CREDENTIALS_PORT, CREDENTIALS_TIMEOUT, PARENT_CID, TLS_PORT,
};
use http_body_util::{BodyExt, Limited};
use hyper_util::rt::TokioIo;
use std::{io, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::AbortHandle,
};
use tokio_rustls::{
    TlsConnector,
    rustls::{self, pki_types::ServerName},
};
use tokio_vsock::{VsockAddr, VsockStream};

use crate::kms::{self, KeyWrapper};

/// Constructs an enclave-only client from a key/alias ARN embedded in the EIF.
///
/// Each HTTPS exchange opens a bounded TLS connection through the fixed parent
/// port. Credentials refresh through the SDK identity cache before expiration.
///
/// # Errors
/// Rejects malformed key configuration. Network errors occur on the first wrap.
pub fn key_wrapper(key_arn: String) -> Result<KeyWrapper, kms::Error> {
    let (scope, _) = kms::arn_parts(&key_arn).ok_or(kms::Error::InvalidKeyArn)?;
    let region = scope.split(':').nth(3).ok_or(kms::Error::InvalidKeyArn)?;
    let hostname = wire::hostname(region).ok_or(kms::Error::InvalidKeyArn)?;
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| kms::Error::InvalidKeyArn)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = SharedHttpConnector::new(KmsConnector {
        hostname,
        tls: TlsConnector::from(Arc::new(tls)),
    });
    let client = Client::from_conf(
        aws_sdk_kms::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(region.to_owned()))
            .credentials_provider(ParentCredentials)
            .http_client(http_client_fn(move |_, _| connector.clone()))
            .build(),
    );
    KeyWrapper::new(&client, key_arn)
}

#[derive(Debug)]
struct ParentCredentials;

impl ParentCredentials {
    async fn load(&self) -> provider::Result {
        tokio::time::timeout(CREDENTIALS_TIMEOUT, async {
            let mut stream =
                VsockStream::connect(VsockAddr::new(PARENT_CID, CREDENTIALS_PORT)).await?;
            wire::read_credentials(&mut stream).await
        })
        .await
        .map_err(|_| CredentialsError::provider_timed_out(CREDENTIALS_TIMEOUT))?
        .map_err(|_| CredentialsError::provider_error("parent credential exchange failed"))
    }
}

impl ProvideCredentials for ParentCredentials {
    fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        future::ProvideCredentials::new(self.load())
    }
}

struct KmsConnector {
    hostname: String,
    tls: TlsConnector,
}
impl std::fmt::Debug for KmsConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KmsConnector")
    }
}

fn transport_error() -> ConnectorError {
    ConnectorError::io(io::Error::other("enclave KMS TLS exchange failed").into())
}

impl HttpConnector for KmsConnector {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let hostname = self.hostname.clone();
        let tls = self.tls.clone();
        HttpConnectorFuture::new(async move {
            tokio::time::timeout(Duration::from_secs(5), async {
                let request = request.try_into_http1x().map_err(|_| transport_error())?;
                validate_destination(&request, &hostname)?;
                let stream = VsockStream::connect(VsockAddr::new(PARENT_CID, TLS_PORT))
                    .await
                    .map_err(|_| transport_error())?;
                exchange(stream, hostname, tls, request).await
            })
            .await
            .map_err(|_| ConnectorError::timeout("enclave KMS TLS exchange timed out".into()))?
        })
    }
}

fn validate_destination(
    request: &http::Request<SdkBody>,
    hostname: &str,
) -> Result<(), ConnectorError> {
    let uri = request.uri();
    if uri.scheme_str() != Some("https")
        || uri.host() != Some(hostname)
        || uri.port_u16().is_some_and(|port| port != 443)
        || uri.path() != "/"
        || uri.query().is_some()
    {
        return Err(ConnectorError::user(
            "unexpected enclave KMS endpoint".into(),
        ));
    }
    Ok(())
}

// Cancellation or completion closes the connection driver, including during a
// wrapping deadline. Each exchange owns one connection and no idle pool.
struct AbortConnection(AbortHandle);
impl Drop for AbortConnection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn exchange(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    hostname: String,
    tls: TlsConnector,
    mut request: http::Request<SdkBody>,
) -> Result<HttpResponse, ConnectorError> {
    if !request.headers().contains_key(http::header::HOST) {
        request.headers_mut().insert(
            http::header::HOST,
            hostname.parse().map_err(|_| transport_error())?,
        );
    }
    *request.uri_mut() = http::Uri::from_static("/");
    let name = ServerName::try_from(hostname).map_err(|_| transport_error())?;
    let stream = tls
        .connect(name, stream)
        .await
        .map_err(|_| transport_error())?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|_| transport_error())?;
    let driver = tokio::spawn(async move {
        // Transport/body errors also propagate through send_request/body collection.
        if connection.await.is_err() {
            tracing::debug!("KMS HTTP connection closed with an error");
        }
    });
    let _guard = AbortConnection(driver.abort_handle());
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| transport_error())?;
    let (parts, body) = response.into_parts();
    // KMS Encrypt responses contain at most a 6144-byte blob plus metadata.
    let bytes = Limited::new(body, 64 * 1024)
        .collect()
        .await
        .map_err(|_| transport_error())?
        .to_bytes();
    http::Response::from_parts(parts, SdkBody::from(bytes))
        .try_into()
        .map_err(|_| transport_error())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_rustls::TlsAcceptor;

    const HOST: &str = "kms.us-east-1.amazonaws.com";

    fn request(url: &str) -> http::Request<SdkBody> {
        http::Request::builder()
            .method("POST")
            .uri(url)
            .body(SdkBody::from("synthetic-plaintext"))
            .unwrap()
    }

    #[test]
    fn only_the_configured_https_endpoint_is_accepted() {
        assert!(validate_destination(&request(&format!("https://{HOST}/")), HOST).is_ok());
        for url in [
            "http://kms.us-east-1.amazonaws.com/",
            "https://kms.us-west-2.amazonaws.com/",
            "https://kms.us-east-1.amazonaws.com:444/",
            "https://kms.us-east-1.amazonaws.com/path",
            "https://kms.us-east-1.amazonaws.com/?query",
        ] {
            assert!(validate_destination(&request(url), HOST).is_err());
        }
    }

    fn tls_pair(trusted: bool) -> (TlsConnector, TlsAcceptor) {
        let cert = rcgen::generate_simple_self_signed(vec![HOST.into()]).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        if trusted {
            roots.add(cert.cert.der().clone()).unwrap();
        }
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (
            TlsConnector::from(Arc::new(client)),
            TlsAcceptor::from(Arc::new(server)),
        )
    }

    #[tokio::test]
    async fn tls_exchange_preserves_the_http_body_and_limits_responses() {
        for size in [10, 65537] {
            let (tls, server) = tls_pair(true);
            let (client_io, server_io) = tokio::io::duplex(4096);
            let task = tokio::spawn(async move {
                let tls = server.accept(server_io).await.unwrap();
                let service = hyper::service::service_fn(
                    move |request: hyper::Request<hyper::body::Incoming>| async move {
                        let body = request.into_body().collect().await.unwrap().to_bytes();
                        assert_eq!(&body[..], b"synthetic-plaintext");
                        Ok::<_, std::convert::Infallible>(http::Response::new(SdkBody::from(
                            vec![b'x'; size],
                        )))
                    },
                );
                // The client closes its per-call connection once it has read the response.
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await
            });
            let result = exchange(
                client_io,
                HOST.into(),
                tls,
                request(&format!("https://{HOST}/")),
            )
            .await;
            assert_eq!(result.is_ok(), size <= 65536);
            if let Ok(response) = result {
                assert_eq!(response.body().bytes().unwrap().len(), size);
            }
            let _closed_connection = task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn untrusted_or_wrong_hostname_certificates_cannot_receive_plaintext() {
        for (trusted, hostname) in [(false, HOST), (true, "wrong.example")] {
            let (tls, server) = tls_pair(trusted);
            let (client_io, server_io) = tokio::io::duplex(4096);
            let task = tokio::spawn(async move { server.accept(server_io).await.is_err() });
            assert!(
                exchange(
                    client_io,
                    hostname.into(),
                    tls,
                    request(&format!("https://{HOST}/"))
                )
                .await
                .is_err()
            );
            assert!(task.await.unwrap());
        }
    }
}
