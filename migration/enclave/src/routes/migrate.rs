use std::{
    io::Read,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::pcp_keys::BackendKeys;
use alkali::asymmetric::seal::curve25519xsalsa20poly1305 as sealedbox;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use di_migration_enclave_primitives::{
    self as enclave_primitives, MigrateRequest, MigrateResponse, SealedMigrationError, pcp_payload,
};
use di_migration_pcp::{MigrationContext, PreparedBiometrics, S3Region, SourcePcp};
use flate2::read::GzDecoder;
use orb_pcp_defs::v1;
use tar::Archive;
use world_id_primitives::{
    Credential, EdDSAPublicKey, poseidon::ds, sponge::hash_bytes_to_field_element,
};

use crate::state::EnclaveState;

struct UnconfiguredKeyDecryptor;

#[async_trait::async_trait]
impl di_migration_pcp::BackendKeyDecryptor for UnconfiguredKeyDecryptor {
    async fn decrypt_backend_key(
        &self,
        _encrypted_private_key: &[u8],
        archive_role: &'static str,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, di_migration_pcp::Error> {
        Err(di_migration_pcp::Error::BackendKeyDecryption(archive_role))
    }
}

/// Ceiling for `hashes.json` inside a PCP; the file is a small JSON manifest.
const MAX_HASHES_JSON_BYTES: usize = 1024 * 1024;
const TEE_SOFTWARE_VERSION: &str = "1.0.0";

/// Opens the app's PCP with this boot's key and seals it back to the app's one-time response
/// key, so the host only ever handles ciphertext. The PCP tiers are encrypted to the
/// device public key supplied at init.
pub async fn handler(
    state: Arc<EnclaveState>,
    request: MigrateRequest,
) -> Result<MigrateResponse, enclave_primitives::Error> {
    let device_public_key: [u8; 32] = STANDARD
        .decode(&request.device_public_key)
        .ok()
        .and_then(|key| key.try_into().ok())
        .ok_or_else(|| {
            tracing::warn!("invalid device public key encoding or length");
            enclave_primitives::Error::InvalidInput
        })?;

    // Opening, migration, and sealed-box encryption are CPU-bound.
    tokio::task::spawn_blocking(move || {
        let result = if request.blob.is_empty() {
            Err(Failure::new(
                enclave_primitives::Error::InvalidInput,
                "The migration request contains no PCP",
            ))
        } else {
            migrate(&state, &request, &device_public_key)
        };
        match result {
            Ok(blob) => Ok(MigrateResponse { blob, error: None }),
            Err(failure) => sealed_failure(failure, &device_public_key),
        }
    })
    .await
    .map_err(|error| {
        if error.is_panic() {
            tracing::error!("migration panicked");
            std::process::exit(1);
        }
        tracing::error!(%error, "migration task was cancelled");
        enclave_primitives::Error::Internal
    })?
}

struct Failure {
    reason: enclave_primitives::Error,
    message: zeroize::Zeroizing<String>,
}

impl Failure {
    fn new(reason: enclave_primitives::Error, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: zeroize::Zeroizing::new(message.into()),
        }
    }
}

fn sealed_failure(
    mut failure: Failure,
    public_key: &[u8; 32],
) -> Result<MigrateResponse, enclave_primitives::Error> {
    // Bound the diagnostic independently of input archive size.
    let mut end = failure.message.len().min(4096);
    while !failure.message.is_char_boundary(end) {
        end -= 1;
    }
    failure.message.truncate(end);
    let mut blob = vec![0; failure.message.len() + sealedbox::OVERHEAD_LENGTH];
    sealedbox::encrypt(failure.message.as_bytes(), public_key, &mut blob).map_err(|error| {
        tracing::error!(?error, "failed to encrypt migration diagnostic");
        enclave_primitives::Error::Internal
    })?;
    Ok(MigrateResponse {
        blob: Vec::new(),
        error: Some(SealedMigrationError {
            reason: failure.reason,
            blob,
        }),
    })
}

fn migrate(
    state: &EnclaveState,
    request: &MigrateRequest,
    device_public_key: &[u8; 32],
) -> Result<Vec<u8>, Failure> {
    let (plaintext, sealer) = state.channel().open(&request.blob).map_err(|error| {
        tracing::warn!(?error, "migrate request was not sealed to this boot");
        Failure::new(
            enclave_primitives::Error::RequestNotOpened,
            "The uploaded PCP could not be opened by this enclave boot",
        )
    })?;
    let pcp_with_credential = pcp_payload::decode(&plaintext).map_err(|reason| {
        Failure::new(
            reason,
            "The uploaded PCP payload is empty or has an unsupported format",
        )
    })?;
    verify_credential(
        state.issuer_pubkey(),
        &request.sub,
        &pcp_with_credential.credential,
        &pcp_with_credential.pcp,
    )?;

    let files = di_migration_pcp::files_from_tar_gz(&pcp_with_credential.pcp).map_err(|error| {
        tracing::warn!(%error, "migrate request PCP archive could not be opened");
        Failure::new(
            enclave_primitives::Error::InvalidPcp,
            format!("Failed to open PCP archive: {error}"),
        )
    })?;
    let source_pcp = parse_source_pcp(state, files)?;
    let prepared_biometrics = pipeline();
    let migrated_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            Failure::new(
                enclave_primitives::Error::Internal,
                "System clock is before the Unix epoch",
            )
        })?
        .as_secs();
    let context = MigrationContext::new(
        TEE_SOFTWARE_VERSION.to_owned(),
        migrated_ts,
        S3Region::UsEast1,
    );

    let key_wrapper = state.key_wrapper().ok_or_else(|| {
        tracing::error!("PCP key wrapping is not configured");
        Failure::new(
            enclave_primitives::Error::Internal,
            "PCP key wrapping is not configured",
        )
    })?;
    let backend_keys = tokio::runtime::Handle::current()
        .block_on(BackendKeys::generate(key_wrapper))
        .map_err(|error| {
            tracing::error!(%error, "failed to generate and wrap PCP backend recipients");
            Failure::new(
                enclave_primitives::Error::Internal,
                format!("Failed to generate and wrap PCP recipients: {error}"),
            )
        })?;
    let recipients = backend_keys.recipients(device_public_key);
    let manifest_signer = state.manifest_signer().ok_or_else(|| {
        tracing::error!("PCP manifest signing is not configured");
        Failure::new(
            enclave_primitives::Error::Internal,
            "PCP manifest signing is not configured",
        )
    })?;
    let package = di_migration_pcp::build(
        &source_pcp,
        &prepared_biometrics,
        &context,
        recipients,
        |digest| tokio::runtime::Handle::current().block_on(manifest_signer.sign(digest)),
    )
    .map_err(|error| {
        tracing::warn!(%error, "failed to build output PCP");
        Failure::new(
            enclave_primitives::Error::FailedToBuildPcp,
            format!("Failed to build output PCP: {error}"),
        )
    })?;

    let blob = sealer.seal(&package.tier0).map_err(|error| {
        tracing::error!(?error, "failed to seal the migrated PCP");
        Failure::new(
            enclave_primitives::Error::Internal,
            "Failed to seal the migrated PCP response",
        )
    })?;
    Ok(blob)
}

fn parse_source_pcp(
    state: &EnclaveState,
    files: di_migration_pcp::Files,
) -> Result<SourcePcp, Failure> {
    let parsed = match state.key_wrapper() {
        Some(key_wrapper) => {
            tokio::runtime::Handle::current().block_on(SourcePcp::parse(files, key_wrapper))
        }
        None => tokio::runtime::Handle::current()
            .block_on(SourcePcp::parse(files, &UnconfiguredKeyDecryptor)),
    };
    parsed.map_err(|error| {
        if matches!(error, di_migration_pcp::Error::BackendKeyDecryption(_)) {
            tracing::error!(%error, dependency = "kms", "source PCP key unwrap failed");
            Failure::new(
                enclave_primitives::Error::Internal,
                format!("Source PCP key unwrap failed: {error}"),
            )
        } else {
            tracing::warn!(%error, "migrate request PCP could not be parsed");
            Failure::new(
                enclave_primitives::Error::InvalidPcp,
                format!("Failed to parse source PCP: {error}"),
            )
        }
    })
}

/// Checks the credential's subject, issuer signature, and PCP `hashes.json` claim.
fn verify_credential(
    issuer_pubkey: &EdDSAPublicKey,
    expected_sub: &str,
    credential_json: &str,
    pcp: &[u8],
) -> Result<(), Failure> {
    let credential: Credential =
        serde_json::from_slice(credential_json.as_bytes()).map_err(|error| {
            tracing::warn!(%error, "failed to deserialize credential");
            Failure::new(
                enclave_primitives::Error::CredentialDeserializationFailed,
                format!("Failed to deserialize credential: {error}"),
            )
        })?;
    if credential.sub.to_string() != expected_sub {
        tracing::warn!("credential sub mismatch");
        return Err(Failure::new(
            enclave_primitives::Error::CredentialSubMismatch,
            "Credential subject does not match the migration subject",
        ));
    }

    let valid = credential
        .verify_signature(issuer_pubkey)
        .map_err(|error| {
            tracing::warn!(%error, "credential signature verification failed");
            Failure::new(
                enclave_primitives::Error::CredentialSignatureVerificationFailed,
                format!("Credential signature verification failed: {error}"),
            )
        })?;
    if !valid {
        tracing::warn!("credential signature is invalid");
        return Err(Failure::new(
            enclave_primitives::Error::CredentialSignatureInvalid,
            "Credential signature is invalid",
        ));
    }

    // claims[0] is Poseidon2(CLAIMS_HASH_V1, raw hashes.json) for a PCP-backed credential.
    let hashes_json = hashes_json_from_pcp(pcp)?;
    let expected_claim =
        hash_bytes_to_field_element(ds::CLAIMS_HASH_V1, &hashes_json).map_err(|_| {
            tracing::warn!("failed to hash hashes.json into a claim");
            Failure::new(
                enclave_primitives::Error::CredentialClaimsMismatch,
                "Failed to hash hashes.json into a credential claim",
            )
        })?;
    let Some(actual_claim) = credential.claims.first() else {
        tracing::warn!("credential carried no claims");
        return Err(Failure::new(
            enclave_primitives::Error::CredentialClaimsMismatch,
            "Credential claims do not match PCP hashes.json",
        ));
    };
    if expected_claim != *actual_claim {
        tracing::warn!("credential claims mismatch");
        return Err(Failure::new(
            enclave_primitives::Error::CredentialClaimsMismatch,
            "Credential claims do not match PCP hashes.json",
        ));
    }
    Ok(())
}

/// Reads `hashes.json` from a gzip-compressed tar PCP without writing to disk.
fn hashes_json_from_pcp(pcp: &[u8]) -> Result<Vec<u8>, Failure> {
    let mut archive = Archive::new(GzDecoder::new(pcp));
    let entries = archive.entries().map_err(|error| {
        tracing::warn!(%error, "PCP is not a gzip tar archive");
        Failure::new(
            enclave_primitives::Error::InvalidInput,
            format!("Failed to read PCP hashes.json: {error}"),
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            tracing::warn!(%error, "failed to read a PCP tar entry");
            Failure::new(
                enclave_primitives::Error::InvalidInput,
                format!("Failed to read PCP hashes.json: {error}"),
            )
        })?;
        let is_hashes = entry
            .path()
            .map(|path| path.as_ref() == Path::new("hashes.json"))
            .map_err(|error| {
                tracing::warn!(%error, "PCP tar entry path is invalid");
                Failure::new(
                    enclave_primitives::Error::InvalidInput,
                    format!("Failed to read PCP hashes.json: {error}"),
                )
            })?;
        if !is_hashes {
            continue;
        }

        let mut hashes_json = Vec::new();
        entry
            .take(MAX_HASHES_JSON_BYTES as u64 + 1)
            .read_to_end(&mut hashes_json)
            .map_err(|error| {
                tracing::warn!(%error, "failed to read hashes.json from PCP");
                Failure::new(
                    enclave_primitives::Error::InvalidInput,
                    format!("Failed to read PCP hashes.json: {error}"),
                )
            })?;
        if hashes_json.is_empty() || hashes_json.len() > MAX_HASHES_JSON_BYTES {
            tracing::warn!("hashes.json missing or too large");
            return Err(Failure::new(
                enclave_primitives::Error::InvalidInput,
                "PCP hashes.json is empty or exceeds its size limit",
            ));
        }
        return Ok(hashes_json);
    }

    tracing::warn!("PCP did not contain hashes.json");
    Err(Failure::new(
        enclave_primitives::Error::InvalidInput,
        "PCP does not contain hashes.json",
    ))
}

// TODO: This is work in progress. Replace these fixed values with the biometric pipeline outputs
// once the biometric pipeline is available in the enclave.
fn pipeline() -> PreparedBiometrics<'static> {
    let normalized = || orb_pcp::NormalizedIrisFrame {
        image: &[1; 16],
        mask: &[2; 16],
        image_resized: &[3; 8],
        mask_resized: &[4; 8],
    };
    let model = || "1.2.3".to_owned();
    let encoding = || "test-di-encoding".to_owned();
    PreparedBiometrics {
        biometric_pipeline_version: "pipeline-1".into(),
        face_embeddings: vec![v1::FaceEmbedding {
            embedding: Some("new-face".into()),
            embedding_type: Some("test-face".into()),
            embedding_version: Some("face-2".into()),
            embedding_inference_backend: Some("test-runtime".into()),
        }],
        di_embeddings: v1::DiIrisEmbeddings {
            embedding_v1: Some(v1::DiIrisEmbeddingV1 {
                model_version: model(),
                embedding_inference_backend: "test-runtime".into(),
                embedding_version: encoding(),
                left_embedding: vec![1, 2],
                left_mirror_embedding: vec![3, 4],
                right_embedding: vec![1, 2],
                right_mirror_embedding: vec![3, 4],
                left_embedding_f32: vec![0.1, 0.2],
                left_mirror_embedding_f32: vec![0.3, 0.4],
                right_embedding_f32: vec![0.1, 0.2],
                right_mirror_embedding_f32: vec![0.3, 0.4],
            }),
        },
        di_embedding_shares: [1_u32, 2, 3].map(|recipient| {
            let base = 10 * recipient;
            v1::DiIrisEmbeddingShares {
                share_v1: Some(v1::DiIrisEmbeddingShareV1 {
                    model_version: model(),
                    shares_version: "test-di-shares".into(),
                    embedding_version: encoding(),
                    left_share: vec![base + 1, base + 2],
                    left_mirror_share: vec![base + 3, base + 4],
                    right_share: vec![base + 1, base + 2],
                    right_mirror_share: vec![base + 3, base + 4],
                }),
            }
        }),
        left_normalized: normalized(),
        right_normalized: normalized(),
        extra_normalized: std::collections::BTreeMap::default(),
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Write, sync::Arc};

    use di_migration_enclave_primitives::{
        self as enclave_primitives, MIGRATION_CHANNEL_DOMAIN, MigrateRequest, pcp_payload,
    };
    use flate2::write::GzEncoder;
    use pontifex::channel::{ChannelConsumer, ChannelDomain, ResponseOpener};
    use world_id_primitives::{Credential, EdDSAPrivateKey, FieldElement};

    use super::handler;
    use crate::{state::EnclaveState, test_support};

    /// Seals `plaintext` to `state`'s key as the app does.
    fn sealed(
        state: &EnclaveState,
        plaintext: &[u8],
        sub: impl Into<String>,
    ) -> (MigrateRequest, ResponseOpener) {
        let consumer = ChannelConsumer::from_unverified_public_key(
            ChannelDomain::new(MIGRATION_CHANNEL_DOMAIN),
            &state.channel().public_key(),
        )
        .expect("valid key");
        let (blob, opener) = consumer.seal_to_enclave(plaintext).expect("should seal");
        (
            MigrateRequest {
                blob: blob.into(),
                sub: sub.into(),
                device_public_key: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=".to_owned(),
            },
            opener,
        )
    }

    /// Builds a gzip-compressed tar PCP whose only file is `hashes.json`, matching orb PCP layout.
    fn pcp_with_hashes_json(hashes_json: &[u8]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut archive = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_path("hashes.json").expect("path");
            header.set_size(hashes_json.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append(&header, hashes_json)
                .expect("append hashes.json");
            archive.finish().expect("finish tar");
        }
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar_bytes).expect("gzip");
        encoder.finish().expect("finish gzip")
    }

    /// Mirrors iris signup: claim raw bytes are `hashes.json`, then Poseidon-hashed into claims[0]
    /// and signed by the issuer (`createClaimFromPcp` → credential signer).
    fn signed_credential_for_pcp(
        issuer: &EdDSAPrivateKey,
        hashes_json: &[u8],
        sub: FieldElement,
    ) -> String {
        let credential = Credential::new()
            .subject(sub)
            .genesis_issued_at(1_700_000_000)
            .expires_at(2_000_000_000)
            .claim(0, hashes_json)
            .expect("claim from hashes.json")
            .sign(issuer)
            .expect("sign");
        serde_json::to_string(&credential).expect("serialize credential")
    }

    #[tokio::test]
    async fn a_source_pcp_must_contain_all_migration_artifacts() {
        let issuer = EdDSAPrivateKey::from_bytes([7u8; 32]);
        let state = Arc::new(test_support::state_with_issuer_pubkey(issuer.public()));

        let hashes_json = br#"{"thumbnail.png":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        let pcp = pcp_with_hashes_json(hashes_json);
        let sub = FieldElement::from(42u64);
        let credential = signed_credential_for_pcp(&issuer, hashes_json, sub);
        let payload = pcp_payload::encode(&pcp, &credential).expect("encode");

        let (request, opener) = sealed(&state, &payload, sub.to_string());
        let _ = opener;
        assert_eq!(
            handler(state, request).await.unwrap().error.unwrap().reason,
            enclave_primitives::Error::InvalidPcp
        );
    }

    #[tokio::test]
    async fn a_credential_with_an_invalid_signature_is_rejected() {
        let issuer = EdDSAPrivateKey::from_bytes([7u8; 32]);
        let state = Arc::new(test_support::state_with_issuer_pubkey(issuer.public()));
        let hashes_json = br#"{\"thumbnail.png\":\"hash\"}"#;
        let pcp = pcp_with_hashes_json(hashes_json);
        let sub = FieldElement::from(42u64);
        let mut credential: serde_json::Value =
            serde_json::from_str(&signed_credential_for_pcp(&issuer, hashes_json, sub))
                .expect("deserialize credential for tampering");
        credential["issuer_version"] = serde_json::json!(1);
        let payload = pcp_payload::encode(&pcp, &credential.to_string()).expect("encode");
        let (request, _) = sealed(&state, &payload, sub.to_string());

        assert_eq!(
            handler(state, request).await.unwrap().error.unwrap().reason,
            enclave_primitives::Error::CredentialSignatureInvalid
        );
    }

    #[tokio::test]
    async fn a_credential_with_an_unexpected_issuer_is_rejected() {
        let issuer = EdDSAPrivateKey::from_bytes([7u8; 32]);
        let expected_issuer = EdDSAPrivateKey::from_bytes([8u8; 32]);
        let state = Arc::new(test_support::state_with_issuer_pubkey(
            expected_issuer.public(),
        ));
        let hashes_json = br#"{\"thumbnail.png\":\"hash\"}"#;
        let pcp = pcp_with_hashes_json(hashes_json);
        let sub = FieldElement::from(42u64);
        let credential = signed_credential_for_pcp(&issuer, hashes_json, sub);
        let payload = pcp_payload::encode(&pcp, &credential).expect("encode");
        let (request, _) = sealed(&state, &payload, sub.to_string());

        assert_eq!(
            handler(state, request).await.unwrap().error.unwrap().reason,
            enclave_primitives::Error::CredentialSignatureVerificationFailed
        );
    }

    #[tokio::test]
    async fn a_blob_sealed_to_another_boot_is_not_opened() {
        let earlier = test_support::state();
        let (request, _) = sealed(
            &earlier,
            &pcp_payload::encode(b"old pcp", "self-custody").expect("encode"),
            "sub",
        );

        let error = handler(Arc::new(test_support::state()), request)
            .await
            .expect("the new boot encrypts a diagnostic");

        assert_eq!(
            error.error.unwrap().reason,
            enclave_primitives::Error::RequestNotOpened
        );
    }

    #[tokio::test]
    async fn a_diagnostic_only_opens_with_the_personal_custody_key() {
        use alkali::asymmetric::seal::curve25519xsalsa20poly1305 as sealedbox;
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let pair = sealedbox::Keypair::generate().unwrap();
        let other = sealedbox::Keypair::generate().unwrap();
        let state = Arc::new(test_support::state());
        let (mut request, _) = sealed(&state, &[9, 1, 2], "sub");
        request.device_public_key = STANDARD.encode(pair.public_key);
        let response = handler(state, request).await.unwrap();
        assert!(response.blob.is_empty());
        let error = response.error.unwrap();
        assert_eq!(error.reason, enclave_primitives::Error::InvalidInput);
        let mut plaintext =
            zeroize::Zeroizing::new(vec![0; error.blob.len() - sealedbox::OVERHEAD_LENGTH]);
        assert!(sealedbox::decrypt(&error.blob, &other, &mut plaintext).is_err());
        sealedbox::decrypt(&error.blob, &pair, &mut plaintext).unwrap();
        assert!(
            std::str::from_utf8(&plaintext)
                .unwrap()
                .contains("unsupported format")
        );
    }

    #[tokio::test]
    async fn malformed_device_public_keys_are_rejected() {
        let state = Arc::new(test_support::state());
        let (request, _) = sealed(&state, b"payload", "sub");
        for key in ["", "not-base64", "YQ=="] {
            let mut request = request.clone();
            request.device_public_key = key.to_owned();
            assert_eq!(
                handler(Arc::clone(&state), request).await,
                Err(enclave_primitives::Error::InvalidInput)
            );
        }
    }

    #[tokio::test]
    async fn an_unknown_payload_or_empty_blob_is_invalid() {
        let state = Arc::new(test_support::state());
        let (unknown, _) = sealed(&state, &[9, 1, 2], "sub");
        let mut empty = unknown.clone();
        empty.blob = Vec::new().into();

        for request in [unknown, empty] {
            assert_eq!(
                handler(Arc::clone(&state), request)
                    .await
                    .unwrap()
                    .error
                    .unwrap()
                    .reason,
                enclave_primitives::Error::InvalidInput
            );
        }
    }
}
