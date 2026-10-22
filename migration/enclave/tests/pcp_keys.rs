//! Synthetic recipient routing, KMS wire compatibility and failure checks.
#[path = "../../pcp/tests/support/mod.rs"]
mod support;

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use alkali::asymmetric::seal::curve25519xsalsa20poly1305 as sealedbox;
use aws_sdk_kms::{
    Client,
    config::{BehaviorVersion, Credentials, Region},
    primitives::Blob,
};
use aws_smithy_runtime_api::client::{
    http::{
        HttpConnector, HttpConnectorFuture, SharedHttpClient, SharedHttpConnector, http_client_fn,
    },
    orchestrator::HttpRequest,
};
use aws_smithy_types::body::SdkBody;

struct TestConnector<F>(F);
impl<F> std::fmt::Debug for TestConnector<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestConnector")
    }
}
impl<F: Fn(HttpRequest) -> HttpConnectorFuture + Send + Sync> HttpConnector for TestConnector<F> {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        (self.0)(request)
    }
}
fn test_client(
    f: impl Fn(HttpRequest) -> HttpConnectorFuture + Send + Sync + 'static,
) -> SharedHttpClient {
    let connector = SharedHttpConnector::new(TestConnector(f));
    http_client_fn(move |_, _| connector.clone())
}
fn infallible_client_fn(
    f: impl Fn(http::Request<SdkBody>) -> http::Response<String> + Send + Sync + 'static,
) -> SharedHttpClient {
    test_client(move |request| {
        HttpConnectorFuture::ready(Ok(f(request.try_into_http1x().unwrap())
            .map(SdkBody::from)
            .try_into()
            .unwrap()))
    })
}
use base64::{Engine, engine::general_purpose::STANDARD};
use di_migration_enclave::{
    kms::{Error, KeyWrapper},
    pcp_keys::{self, BackendKeys},
};
use di_migration_pcp::{validate_build_inputs, verify_completed_pcp};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::{open_tier, unseal};

const KEY_ARN: &str = "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000001";

fn config() -> aws_sdk_kms::config::Builder {
    aws_sdk_kms::config::Builder::new()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .retry_config(
            aws_sdk_kms::config::retry::RetryConfig::standard()
                .with_initial_backoff(std::time::Duration::ZERO),
        )
        .credentials_provider(Credentials::new("test", "test", None, None, "synthetic"))
}

fn response(body: Value) -> http::Response<String> {
    http::Response::builder()
        .status(200)
        .body(body.to_string())
        .unwrap()
}

// The fake service uses a generated sealed-box key to wrap bytes. No secret is
// stored in a fixture; LocalStack below verifies the real KMS operation format.
fn mock_kms() -> (KeyWrapper, Arc<sealedbox::Keypair>) {
    let master = Arc::new(sealedbox::Keypair::generate().unwrap());
    let key = master.clone();
    let http = infallible_client_fn(move |request| {
        assert_eq!(request.headers()["x-amz-target"], "TrentService.Encrypt");
        let body: Value = serde_json::from_slice(request.body().bytes().unwrap()).unwrap();
        assert_eq!(body["KeyId"], KEY_ARN);
        assert_eq!(body["EncryptionAlgorithm"], "SYMMETRIC_DEFAULT");
        assert!(body.get("EncryptionContext").is_none());
        let plaintext = STANDARD
            .decode(body["Plaintext"].as_str().unwrap())
            .unwrap();
        assert_eq!(plaintext.len(), 32); // Raw key bytes, not a Base64 string.
        let mut ciphertext = vec![0; plaintext.len() + sealedbox::OVERHEAD_LENGTH];
        sealedbox::encrypt(&plaintext, &key.public_key, &mut ciphertext).unwrap();
        response(
            json!({"KeyId": KEY_ARN, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
            "CiphertextBlob": STANDARD.encode(ciphertext)}),
        )
    });
    (
        KeyWrapper::new(
            &Client::from_conf(config().http_client(http).build()),
            KEY_ARN.into(),
        )
        .unwrap(),
        master,
    )
}

fn recover_key(bytes: &[u8], public_key: &[u8]) -> sealedbox::Keypair {
    let mut secret = sealedbox::PrivateKey::new_empty().unwrap();
    secret.copy_from_slice(bytes);
    let pair = sealedbox::Keypair::from_private_key(&secret).unwrap();
    assert_eq!(pair.public_key.as_slice(), public_key);
    pair
}

async fn check_package(keys: &BackendKeys, unwrap: impl Fn(&str) -> Vec<u8>) {
    let mut input = support::source_files("2.8");
    input.insert(
        "face_ir_and_thermal/face_ir.png".into(),
        b"synthetic-ir".to_vec(),
    );
    input.insert(
        "face_ir_and_thermal/thermal.png".into(),
        b"synthetic-thermal".to_vec(),
    );
    input.insert("fraud/scc_rgb.png".into(), b"synthetic-fraud".to_vec());
    support::refresh_source_manifest(&mut input);
    let source = support::parse_source_async(input).await.unwrap();
    let bio = support::pipeline();
    let ctx = support::context();
    let user = sealedbox::Keypair::generate().unwrap();
    validate_build_inputs(&source, &bio, &ctx, &user.public_key).unwrap();
    let mut digest = None;
    let output = di_migration_pcp::build(
        &source,
        &bio,
        &ctx,
        keys.recipients(&user.public_key),
        |d| {
            digest = Some(*d);
            Ok::<_, std::convert::Infallible>(support::SIGNATURE.to_vec())
        },
    )
    .unwrap();
    let files = open_tier(&output.tier0, &user);
    assert_eq!(
        digest.unwrap(),
        <[u8; 32]>::from(Sha256::digest(&files["hashes.json"]))
    );
    let serialized: Value = serde_json::from_slice(&files["backend_keys.json"]).unwrap();
    let recipients = keys.recipients(&user.public_key).backend_keys;
    let mut public_keys = std::collections::BTreeSet::new();
    let [iris, normalized_iris, face, tier2] = [
        ("iris", recipients.iris),
        ("normalized_iris", recipients.normalized_iris),
        ("face", recipients.face),
        ("tier2", recipients.tier2),
    ]
    .map(|(role, key)| {
        assert!(public_keys.insert(*key.public_key));
        assert_eq!(
            serialized[role]["public_key"],
            STANDARD.encode(key.public_key)
        );
        assert_eq!(
            serialized[role]["encrypted_private_key"],
            key.encrypted_private_key
        );
        recover_key(&unwrap(key.encrypted_private_key), key.public_key)
    });
    for (name, ciphertext) in &files {
        if name.ends_with(".tar") {
            let mut wrong_output = vec![0; ciphertext.len() - sealedbox::OVERHEAD_LENGTH];
            assert!(sealedbox::decrypt(ciphertext, &user, &mut wrong_output).is_err());
        }
    }
    let files = support::open(
        &output,
        &support::OutputKeys {
            user,
            iris,
            normalized_iris,
            face,
            tier2,
        },
    );
    verify_completed_pcp(&source, &bio, &ctx, &files).unwrap();
}

#[tokio::test]
async fn wrapped_keys_build_a_package_that_opens_with_the_recovered_keys() {
    let (wrapper, master) = mock_kms();
    let keys = BackendKeys::generate(&wrapper).await.unwrap();
    let next = BackendKeys::generate(&wrapper).await.unwrap();
    assert_ne!(
        keys.recipients(&[0; 32]).backend_keys.face.public_key,
        next.recipients(&[0; 32]).backend_keys.face.public_key
    );
    check_package(&keys, |envelope| {
        unseal(&STANDARD.decode(envelope).unwrap(), &master)
    })
    .await;
}

#[tokio::test]
async fn partial_failure_stops_wrapping_and_returns_no_bundle() {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let http = infallible_client_fn(move |_| {
        if count.fetch_add(1, Ordering::SeqCst) == 1 {
            return http::Response::builder().status(400).body(
                json!({"__type":"AccessDeniedException", "message":"sensitive-upstream-detail"}).to_string()
            ).unwrap();
        }
        response(
            json!({"KeyId":KEY_ARN, "EncryptionAlgorithm":"SYMMETRIC_DEFAULT", "CiphertextBlob":"AQ=="}),
        )
    });
    let wrapper = KeyWrapper::new(
        &Client::from_conf(config().http_client(http).build()),
        KEY_ARN.into(),
    )
    .unwrap();
    let error = BackendKeys::generate(&wrapper).await.err().unwrap();
    assert!(matches!(
        error,
        pcp_keys::Error::Wrapping {
            archive_role: "normalized_iris",
            source: Error::AccessDenied
        }
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn an_unresponsive_kms_is_bounded() {
    let wrapper = KeyWrapper::new(
        &Client::from_conf(
            config()
                .http_client(test_client(|_| {
                    HttpConnectorFuture::new(std::future::pending())
                }))
                .build(),
        ),
        KEY_ARN.into(),
    )
    .unwrap();
    let started = tokio::time::Instant::now();
    assert_eq!(
        wrapper.encrypt(&[0; 32], "synthetic").await,
        Err(Error::Timeout)
    );
    assert!(started.elapsed() <= std::time::Duration::from_secs(10));
}

#[tokio::test]
async fn invalid_kms_responses_are_rejected() {
    for body in [
        json!({"KeyId":KEY_ARN, "EncryptionAlgorithm":"SYMMETRIC_DEFAULT"}),
        json!({"KeyId":KEY_ARN, "EncryptionAlgorithm":"SYMMETRIC_DEFAULT", "CiphertextBlob":""}),
        json!({"KeyId":KEY_ARN, "EncryptionAlgorithm":"RSAES_OAEP_SHA_256", "CiphertextBlob":"AQ=="}),
    ] {
        let http = infallible_client_fn(move |_| response(body.clone()));
        let wrapper = KeyWrapper::new(
            &Client::from_conf(config().http_client(http).build()),
            KEY_ARN.into(),
        )
        .unwrap();
        assert_eq!(
            wrapper.encrypt(&[0; 32], "synthetic").await,
            Err(Error::InvalidResponse)
        );
    }
}

#[tokio::test]
#[ignore = "requires LOCALSTACK_ENDPOINT with KMS"]
async fn localstack_ciphertexts_round_trip_into_the_archive_keys() {
    let endpoint = std::env::var("LOCALSTACK_ENDPOINT").expect("LOCALSTACK_ENDPOINT is required");
    let client = Client::from_conf(config().endpoint_url(endpoint).build());
    let created = client.create_key().send().await.unwrap();
    let arn = created.key_metadata.unwrap().arn.unwrap();
    let alias = format!("alias/pcp-test-{}", arn.rsplit('/').next().unwrap());
    client
        .create_alias()
        .alias_name(&alias)
        .target_key_id(&arn)
        .send()
        .await
        .unwrap();
    let alias_arn = format!("{}:{alias}", arn.rsplit_once(':').unwrap().0);
    let wrapper = KeyWrapper::new(&client, alias_arn).unwrap();
    let result = BackendKeys::generate(&wrapper).await;
    let keys = result.unwrap();
    let recipients = keys.recipients(&[0; 32]).backend_keys;
    let mut unwrapped = std::collections::BTreeMap::new();
    for key in [
        recipients.iris,
        recipients.normalized_iris,
        recipients.face,
        recipients.tier2,
    ] {
        let result = client
            .decrypt()
            .key_id(&arn)
            .ciphertext_blob(Blob::new(
                STANDARD.decode(key.encrypted_private_key).unwrap(),
            ))
            .send()
            .await
            .unwrap();
        unwrapped.insert(
            key.encrypted_private_key.to_owned(),
            result.plaintext.unwrap().into_inner(),
        );
    }
    client
        .delete_alias()
        .alias_name(alias)
        .send()
        .await
        .unwrap();
    client
        .schedule_key_deletion()
        .key_id(&arn)
        .pending_window_in_days(7)
        .send()
        .await
        .unwrap();
    check_package(&keys, |envelope| unwrapped[envelope].clone()).await;
}

#[tokio::test]
async fn the_configured_alias_is_forwarded_to_kms() {
    const ALIAS: &str = "arn:aws:kms:us-east-1:000000000000:alias/test";
    let http = infallible_client_fn(|request| {
        let body: Value = serde_json::from_slice(request.body().bytes().unwrap()).unwrap();
        assert_eq!(body["KeyId"], ALIAS);
        response(
            json!({"KeyId":KEY_ARN, "EncryptionAlgorithm":"SYMMETRIC_DEFAULT", "CiphertextBlob":"AQ=="}),
        )
    });
    let wrapper = KeyWrapper::new(
        &Client::from_conf(config().http_client(http).build()),
        ALIAS.into(),
    )
    .unwrap();
    assert_eq!(
        wrapper.encrypt(&[0; 32], "synthetic").await.unwrap(),
        "AQ=="
    );
}

#[derive(Clone, Default)]
struct Logs(Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn failures_report_the_archive_role_without_upstream_payloads() {
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::layer::SubscriberExt;
    // Parallel tests need a stable global default alongside this scoped capture.
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(tracing_subscriber::filter::LevelFilter::OFF),
    )
    .unwrap();
    let http = infallible_client_fn(|_| {
        http::Response::builder()
            .status(400)
            .body(json!({"__type":"sensitive-upstream-detail", "message":"sensitive-upstream-detail"}).to_string())
            .unwrap()
    });
    let wrapper = KeyWrapper::new(
        &Client::from_conf(config().http_client(http).build()),
        KEY_ARN.into(),
    )
    .unwrap();
    let logs = Logs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    let result = BackendKeys::generate(&wrapper)
        .with_subscriber(subscriber)
        .await;
    assert!(matches!(
        result,
        Err(pcp_keys::Error::Wrapping {
            archive_role: "iris",
            source: Error::RequestFailed,
        })
    ));
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(!text.contains("sensitive-upstream-detail"), "{text}");
    assert!(text.contains("PCP key encryption failed"), "{text}");
    assert!(text.contains("archive_role=\"iris\""), "{text}");
    assert!(text.contains("dependency=\"kms\""), "{text}");
}

#[tokio::test]
async fn configuration_requires_a_full_key_or_alias_arn_in_the_client_region() {
    let client = Client::from_conf(config().build());
    for arn in [KEY_ARN, "arn:aws:kms:us-east-1:000000000000:alias/test"] {
        assert!(KeyWrapper::new(&client, arn.into()).is_ok());
    }
    for arn in [
        "",
        "alias/test",
        "arn:aws:kms:us-west-2:000000000000:key/test",
        "arn:aws:kms:us-east-1::alias/test",
        "arn:aws:kms:us-east-1:000000000000:key/",
    ] {
        assert!(matches!(
            KeyWrapper::new(&client, arn.into()),
            Err(Error::InvalidConfiguration)
        ));
    }
}
