//! Synthetic recipient routing, KMS wire compatibility and failure checks.
#[path = "../../pcp/tests/support/mod.rs"]
mod support;

use std::{
    io::Read,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
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
    pcp_keys::{self, WrappedPcpKeys},
};
use di_migration_pcp::{Files, SourcePcp, verify_completed_pcp};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const KEY_ARN: &str = "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000001";

fn config() -> aws_sdk_kms::config::Builder {
    aws_sdk_kms::config::Builder::new()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
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
        ),
        master,
    )
}

fn unseal(ciphertext: &[u8], pair: &sealedbox::Keypair) -> Vec<u8> {
    let mut bytes = vec![0; ciphertext.len() - sealedbox::OVERHEAD_LENGTH];
    sealedbox::decrypt(ciphertext, pair, &mut bytes).unwrap();
    bytes
}

fn untar(bytes: &[u8]) -> Files {
    tar::Archive::new(bytes)
        .entries()
        .unwrap()
        .map(|entry| {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_str().unwrap().to_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            (path, bytes)
        })
        .collect()
}

fn unpack(ciphertext: &[u8], user: &sealedbox::Keypair) -> Files {
    let gzip = unseal(ciphertext, user);
    let mut bytes = Vec::new();
    flate2::read::GzDecoder::new(gzip.as_slice())
        .read_to_end(&mut bytes)
        .unwrap();
    untar(&bytes)
}

fn recover_key(bytes: &[u8], public_key: &[u8]) -> sealedbox::Keypair {
    let mut secret = sealedbox::PrivateKey::new_empty().unwrap();
    secret.copy_from_slice(bytes);
    let pair = sealedbox::Keypair::from_private_key(&secret).unwrap();
    assert_eq!(pair.public_key.as_slice(), public_key);
    pair
}

fn check_package(keys: &WrappedPcpKeys, unwrap: impl Fn(&str) -> Vec<u8>) {
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
    let source = SourcePcp::parse(input).unwrap();
    let bio = support::pipeline();
    let ctx = support::context();
    let user = sealedbox::Keypair::generate().unwrap();
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
    assert!(unpack(&output.tier1, &user).is_empty());
    assert!(unpack(&output.tier2, &user).is_empty());
    let mut files = unpack(&output.tier0, &user);
    assert_eq!(
        digest.unwrap(),
        <[u8; 32]>::from(Sha256::digest(&files["hashes.json"]))
    );
    let serialized: Value = serde_json::from_slice(&files["backend_keys.json"]).unwrap();
    let recipients = keys.recipients(&user.public_key).backend_keys;
    let mut public_keys = std::collections::BTreeSet::new();
    for (role, key, archives) in [
        ("iris", recipients.iris, &["iris"][..]),
        (
            "normalized_iris",
            recipients.normalized_iris,
            &["normalized_iris"][..],
        ),
        ("face", recipients.face, &["face", "fraud"][..]),
        ("tier2", recipients.tier2, &["face_ir_and_thermal"][..]),
    ] {
        assert!(public_keys.insert(*key.public_key));
        assert_eq!(
            serialized[role]["public_key"],
            STANDARD.encode(key.public_key)
        );
        assert_eq!(
            serialized[role]["encrypted_private_key"],
            key.encrypted_private_key
        );
        let pair = recover_key(&unwrap(key.encrypted_private_key), key.public_key);
        for stem in archives {
            let ciphertext = files.remove(&format!("{stem}.tar")).unwrap();
            let mut wrong_output = vec![0; ciphertext.len() - sealedbox::OVERHEAD_LENGTH];
            assert!(sealedbox::decrypt(&ciphertext, &user, &mut wrong_output).is_err());
            for (name, bytes) in untar(&unseal(&ciphertext, &pair)) {
                files.insert(format!("{stem}/{name}"), bytes);
            }
        }
    }
    verify_completed_pcp(&source, &bio, &ctx, &files).unwrap();
}

#[tokio::test]
async fn wrapped_keys_build_a_package_that_opens_with_the_recovered_keys() {
    let (wrapper, master) = mock_kms();
    let keys = WrappedPcpKeys::generate(&wrapper).await.unwrap();
    let next = WrappedPcpKeys::generate(&wrapper).await.unwrap();
    assert_ne!(
        keys.recipients(&[0; 32]).backend_keys.face.public_key,
        next.recipients(&[0; 32]).backend_keys.face.public_key
    );
    check_package(&keys, |envelope| {
        unseal(&STANDARD.decode(envelope).unwrap(), &master)
    });
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
    );
    let error = WrappedPcpKeys::generate(&wrapper).await.err().unwrap();
    assert!(matches!(
        error,
        pcp_keys::Error::Wrapping {
            role: "normalized_iris",
            source: Error::AccessDenied
        }
    ));
    assert!(!format!("{error:?}").contains("sensitive-upstream-detail"));
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
    );
    assert_eq!(wrapper.wrap(&[0; 32]).await, Err(Error::Timeout));
}

#[tokio::test]
async fn invalid_kms_responses_are_rejected() {
    for body in [
        json!({"KeyId":KEY_ARN, "EncryptionAlgorithm":"SYMMETRIC_DEFAULT"}),
        json!({"KeyId":KEY_ARN, "EncryptionAlgorithm":"SYMMETRIC_DEFAULT", "CiphertextBlob":""}),
        json!({"KeyId":KEY_ARN, "EncryptionAlgorithm":"RSAES_OAEP_SHA_256", "CiphertextBlob":"AQ=="}),
        json!({"KeyId":KEY_ARN, "EncryptionAlgorithm":"SYMMETRIC_DEFAULT", "CiphertextBlob":STANDARD.encode(vec![0;6145])}),
    ] {
        let http = infallible_client_fn(move |_| response(body.clone()));
        let wrapper = KeyWrapper::new(
            &Client::from_conf(config().http_client(http).build()),
            KEY_ARN.into(),
        );
        assert_eq!(wrapper.wrap(&[0; 32]).await, Err(Error::InvalidResponse));
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
    let wrapper = KeyWrapper::new(&client, alias_arn);
    let result = WrappedPcpKeys::generate(&wrapper).await;
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
    check_package(&keys, |envelope| unwrapped[envelope].clone());
}

#[tokio::test(start_paused = true)]
async fn transient_errors_retry_twice_with_the_same_plaintext() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let http = infallible_client_fn(move |request| {
        let body: Value = serde_json::from_slice(request.body().bytes().unwrap()).unwrap();
        assert_eq!(
            STANDARD
                .decode(body["Plaintext"].as_str().unwrap())
                .unwrap(),
            [42; 32]
        );
        counter.fetch_add(1, Ordering::SeqCst);
        http::Response::builder()
            .status(500)
            .body(json!({"__type":"KMSInternalException"}).to_string())
            .unwrap()
    });
    let wrapper = KeyWrapper::new(
        &Client::from_conf(config().http_client(http).build()),
        KEY_ARN.into(),
    );
    assert_eq!(wrapper.wrap(&[42; 32]).await, Err(Error::RequestFailed));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
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
    );
    assert_eq!(wrapper.wrap(&[0; 32]).await.unwrap(), "AQ==");
}
