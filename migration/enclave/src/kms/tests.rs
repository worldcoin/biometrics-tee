use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use aws_sdk_kms::config::{BehaviorVersion, Credentials, Region};
use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
use aws_smithy_runtime_api::client::{
    http::{HttpConnector, HttpConnectorFuture, SharedHttpConnector, http_client_fn},
    orchestrator::HttpRequest,
};

struct Connector<F>(F);
impl<F> std::fmt::Debug for Connector<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SyntheticKmsConnector")
    }
}
impl<F: Fn(HttpRequest) -> HttpConnectorFuture + Send + Sync> HttpConnector for Connector<F> {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        (self.0)(request)
    }
}

fn wrapper(f: impl Fn(HttpRequest) -> HttpConnectorFuture + Send + Sync + 'static) -> KeyWrapper {
    let connector = SharedHttpConnector::new(Connector(f));
    let config = aws_sdk_kms::config::Builder::new()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .time_source(aws_smithy_async::time::StaticTimeSource::new(
            std::time::UNIX_EPOCH,
        ))
        .credentials_provider(Credentials::new("test", "test", None, None, "synthetic"))
        .http_client(http_client_fn(move |_, _| connector.clone()))
        .build();
    KeyWrapper::new(&Client::from_conf(config), "alias/synthetic".into())
}

fn tracked_body() -> (Bytes, Arc<AtomicBool>) {
    let erased = Arc::new(AtomicBool::new(false));
    let mut body = SecretBody::new("alias/synthetic", &[42; 32]).unwrap();
    body.erased = Some(erased.clone());
    (Bytes::from_owner(body), erased)
}

#[test]
fn body_encodes_the_key_and_escapes_the_identifier() {
    let id = "alias/synthetic\"\\\n";
    let body = SecretBody::new(id, &[42; 32]).unwrap();
    let value: serde_json::Value = serde_json::from_slice(body.as_ref()).unwrap();
    assert_eq!(value["KeyId"], id);
    assert_eq!(value["EncryptionAlgorithm"], "SYMMETRIC_DEFAULT");
    assert_eq!(value["Plaintext"], STANDARD.encode([42; 32]));
}

#[test]
fn sdk_body_clones_share_the_allocation_and_erase_on_last_drop() {
    let (bytes, erased) = tracked_body();
    let pointer = bytes.as_ptr();
    let body = SdkBody::from(bytes);
    let retry = body.try_clone().unwrap();
    assert_eq!(body.bytes().unwrap().as_ptr(), pointer);
    assert_eq!(retry.bytes().unwrap().as_ptr(), pointer);
    drop(body);
    assert!(!erased.load(Ordering::SeqCst));
    drop(retry);
    assert!(erased.load(Ordering::SeqCst));
}

#[tokio::test]
async fn completion_and_service_failure_erase_the_request() {
    for status in [200, 400] {
        let (body, erased) = tracked_body();
        let pointer = body.as_ptr() as usize;
        let wrapper = wrapper(move |request| {
            assert_eq!(request.body().bytes().unwrap().as_ptr() as usize, pointer);
            assert_eq!(
                request.headers().get("content-length").unwrap(),
                request.body().bytes().unwrap().len().to_string()
            );
            // Recompute SigV4 over the body on the wire, proving that the
            // zeroizing body was installed before the SDK signed the request.
            let identity = Credentials::new("test", "test", None, None, "synthetic").into();
            let authorization = request.headers().get("authorization").unwrap();
            let signed_headers = authorization
                .split("SignedHeaders=")
                .nth(1)
                .unwrap()
                .split(',')
                .next()
                .unwrap();
            let params = aws_sigv4::sign::v4::SigningParams::builder()
                .identity(&identity)
                .region("us-east-1")
                .name("kms")
                .time(std::time::UNIX_EPOCH)
                .settings(SigningSettings::default())
                .build()
                .unwrap()
                .into();
            let signable = SignableRequest::new(
                request.method(),
                request.uri(),
                request
                    .headers()
                    .iter()
                    .filter(|(name, _)| signed_headers.split(';').any(|signed| signed == *name)),
                SignableBody::Bytes(request.body().bytes().unwrap()),
            )
            .unwrap();
            let signature = sign(signable, &params).unwrap();
            assert!(
                request
                    .headers()
                    .get("authorization")
                    .unwrap()
                    .ends_with(&format!("Signature={}", signature.signature()))
            );
            let response = if status == 200 {
                r#"{"EncryptionAlgorithm":"SYMMETRIC_DEFAULT","CiphertextBlob":"AQ=="}"#
            } else {
                r#"{"__type":"AccessDeniedException"}"#
            };
            HttpConnectorFuture::ready(Ok(http::Response::builder()
                .status(status)
                .body(SdkBody::from(response))
                .unwrap()
                .try_into()
                .unwrap()))
        });
        let result = wrapper.send(body).await;
        assert_eq!(
            result,
            if status == 200 {
                Ok("AQ==".into())
            } else {
                Err(Error::AccessDenied)
            }
        );
        assert!(erased.load(Ordering::SeqCst));
    }
}

#[tokio::test(start_paused = true)]
async fn timeout_and_cancellation_erase_an_in_flight_request() {
    for cancel in [false, true] {
        let (body, erased) = tracked_body();
        let started = Arc::new(AtomicBool::new(false));
        let observed = started.clone();
        let wrapper = wrapper(move |request| {
            observed.store(true, Ordering::SeqCst);
            HttpConnectorFuture::new(async move {
                std::future::pending::<()>().await;
                drop(request);
                unreachable!()
            })
        });
        let mut operation = Box::pin(wrapper.send(body));
        if cancel {
            assert!(
                tokio::time::timeout(Duration::from_millis(1), &mut operation)
                    .await
                    .is_err()
            );
            assert!(started.load(Ordering::SeqCst));
            assert!(!erased.load(Ordering::SeqCst));
            drop(operation);
        } else {
            assert_eq!(operation.await, Err(Error::Timeout));
        }
        assert!(erased.load(Ordering::SeqCst));
    }
}
