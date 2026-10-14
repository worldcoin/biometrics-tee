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

const KEY_ARN: &str = "arn:aws:kms:us-east-1:000000000000:key/synthetic";

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
    KeyWrapper::new(&Client::from_conf(config), KEY_ARN.into()).unwrap()
}

pub fn tracked_body() -> (Bytes, Arc<AtomicBool>) {
    let erased = Arc::new(AtomicBool::new(false));
    let mut body = SecretBody::new(KEY_ARN, &[42; 32]);
    body.erased = Some(erased.clone());
    (Bytes::from_owner(body), erased)
}

#[test]
fn body_encodes_the_key_and_escapes_the_identifier() {
    let id = "alias/synthetic\"\\\n";
    let body = SecretBody::new(id, &[42; 32]);
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

#[tokio::test(start_paused = true)]
async fn completion_and_service_failure_erase_the_request() {
    for status in [200, 400, 500] {
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
            let response = match status {
                200 => {
                    r#"{"KeyId":"arn:aws:kms:us-east-1:000000000000:key/synthetic","EncryptionAlgorithm":"SYMMETRIC_DEFAULT","CiphertextBlob":"AQ=="}"#
                }
                400 => r#"{"__type":"AccessDeniedException"}"#,
                _ => r#"{"__type":"KMSInternalException"}"#,
            };
            HttpConnectorFuture::ready(Ok(http::Response::builder()
                .status(status)
                .body(SdkBody::from(response))
                .unwrap()
                .try_into()
                .unwrap()))
        });
        let result = wrapper.send(body, "synthetic").await;
        assert_eq!(
            result,
            match status {
                200 => Ok("AQ==".into()),
                400 => Err(Error::AccessDenied),
                _ => Err(Error::ServiceUnavailable),
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
        let mut operation = Box::pin(wrapper.send(body, "synthetic"));
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

#[test]
fn configuration_requires_a_full_regional_kms_arn_and_preserves_retry_policy() {
    use aws_sdk_kms::config::retry::ReconnectMode;
    let base = wrapper(|_| panic!("configuration must not send requests"));
    let retry = RetryConfig::adaptive()
        .with_initial_backoff(Duration::from_millis(20))
        .with_max_backoff(Duration::from_millis(80))
        .with_reconnect_mode(ReconnectMode::ReuseAllConnections);
    let client = Client::from_conf(
        base.client
            .config()
            .to_builder()
            .retry_config(retry.clone())
            .build(),
    );
    for arn in [
        KEY_ARN,
        "arn:aws:kms:us-east-1:000000000000:alias/synthetic",
    ] {
        let configured = KeyWrapper::new(&client, arn.into()).unwrap();
        let actual = configured.client.config().retry_config().unwrap();
        assert_eq!(actual.mode(), retry.mode());
        assert_eq!(actual.initial_backoff(), retry.initial_backoff());
        assert_eq!(actual.max_backoff(), retry.max_backoff());
        assert_eq!(actual.reconnect_mode(), retry.reconnect_mode());
        assert_eq!(actual.max_attempts(), 2);
    }
    for arn in [
        "",
        "alias/synthetic",
        "synthetic-key-id",
        "arn:aws:kms:us-west-2:000000000000:alias/synthetic",
        "arn:aws:s3:us-east-1:000000000000:key/synthetic",
        "arn:aws:kms:us-east-1::key/synthetic",
        "arn:aws:kms:us-east-1:not-an-account:key/synthetic",
        "arn:aws:kms:us-east-1:000000000000:alias/",
        "arn:aws:kms:us-east-1:000000000000:other/synthetic",
    ] {
        assert!(matches!(
            KeyWrapper::new(&client, arn.into()),
            Err(Error::InvalidConfiguration)
        ));
    }
}

#[tokio::test]
async fn unsupported_sdk_fields_fail_before_transmission_and_erase_the_body() {
    let wrapper = wrapper(|_| panic!("mismatched requests must not reach KMS"));
    for (field, value) in [
        (
            "EncryptionContext",
            serde_json::json!({"purpose":"synthetic"}),
        ),
        ("GrantTokens", serde_json::json!(["synthetic"])),
        (
            "EncryptionAlgorithm",
            serde_json::json!("RSAES_OAEP_SHA_256"),
        ),
        ("KeyId", serde_json::json!("another-key")),
    ] {
        let expected = serde_json::json!({"KeyId":KEY_ARN, "Plaintext":"", "EncryptionAlgorithm":"SYMMETRIC_DEFAULT"});
        let mut unexpected = expected.clone();
        unexpected[field] = value;
        let (body, erased) = tracked_body();
        let result = wrapper
            .client
            .encrypt()
            .key_id(KEY_ARN)
            .plaintext(Blob::new(Vec::new()))
            .encryption_algorithm(EncryptionAlgorithmSpec::SymmetricDefault)
            .customize()
            .mutate_request(move |request| {
                *request.body_mut() = SdkBody::from(unexpected.to_string());
            })
            .map_request(move |request| install_secret_body(request, &expected, &body))
            .send()
            .await;
        assert_eq!(classify(&result.unwrap_err()), Error::InvalidRequest);
        assert!(erased.load(Ordering::SeqCst));
    }
}

#[test]
fn local_failures_are_classified_without_exposing_their_sources() {
    use aws_smithy_runtime_api::client::result::ConnectorError;
    let errors = [
        (
            SdkError::dispatch_failure(ConnectorError::timeout("sensitive-detail".into())),
            Error::Timeout,
        ),
        (
            SdkError::dispatch_failure(ConnectorError::io(
                std::io::Error::other("sensitive-detail").into(),
            )),
            Error::Transport,
        ),
        (
            SdkError::construction_failure(CredentialsError::provider_error("sensitive-detail")),
            Error::Credentials,
        ),
        (
            SdkError::construction_failure(CredentialsError::provider_timed_out(
                Duration::from_secs(3),
            )),
            Error::Timeout,
        ),
    ];
    for (sdk_error, expected) in errors {
        assert_eq!(classify(&sdk_error), expected);
    }
}
