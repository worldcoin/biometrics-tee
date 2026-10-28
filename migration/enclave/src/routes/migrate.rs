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
    self as enclave_primitives, MAX_MIGRATION_DIAGNOSTIC_BYTES, MigrateError, MigrateRequest,
    MigrateResponse, pcp_payload,
};
use di_migration_pcp::{MigrationContext, PreparedBiometrics, S3Region, SourcePcp};
use di_worker_protocol::migration::{FailureCode, MigrationResult};
use flate2::read::GzDecoder;
use orb_pcp_defs::v1;
use pontifex::channel::ResponseSealer;
use rand::rngs::OsRng;
use tar::Archive;
use world_id_primitives::{
    Credential, EdDSAPublicKey, poseidon::ds, sponge::hash_bytes_to_field_element,
};

use zeroize::Zeroizing;

use crate::state::EnclaveState;

/// Ceiling for `hashes.json` inside a PCP; the file is a small JSON manifest.
const MAX_HASHES_JSON_BYTES: usize = 1024 * 1024;
const TEE_SOFTWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Opens the app's PCP with this boot's key and seals it back to the app's one-time response
/// key, so the host only ever handles ciphertext. The PCP tiers are encrypted to the
/// device public key supplied at init.
pub async fn handler(
    state: Arc<EnclaveState>,
    request: MigrateRequest,
) -> Result<MigrateResponse, MigrateError> {
    if request.blob.is_empty() {
        tracing::warn!("migrate request carried no blob");
        return Err(enclave_primitives::Error::InvalidInput.into());
    }

    let device_public_key: [u8; 32] = STANDARD
        .decode(&request.device_public_key)
        .ok()
        .and_then(|key| key.try_into().ok())
        .ok_or_else(|| {
            tracing::warn!("invalid device public key encoding or length");
            enclave_primitives::Error::InvalidInput
        })?;

    // Opening and sealing are CPU-bound; keep them off the async workers.
    tokio::task::spawn_blocking(move || -> Result<MigrateResponse, MigrateError> {
        let (plaintext, sealer) = state.channel().open(&request.blob).map_err(|error| {
            tracing::warn!(?error, "migrate request was not sealed to this boot");
            enclave_primitives::Error::RequestNotOpened
        })?;
        let pcp_with_credential = pcp_payload::decode(&plaintext).inspect_err(|_| {
            tracing::warn!("migrate request carried an unknown payload");
        })?;
        verify_credential(
            state.issuer_pubkey(),
            &request.sub,
            &pcp_with_credential.credential,
            &pcp_with_credential.pcp,
        )?;

        let files =
            di_migration_pcp::files_from_tar_gz(&pcp_with_credential.pcp).map_err(|error| {
                tracing::warn!(%error, "migrate request PCP archive could not be opened");
                enclave_primitives::Error::InvalidPcp
            })?;
        let source_pcp = parse_source_pcp(&state, files)?;
        let (biometrics, debug_report) = run_pipeline(&state, &source_pcp);
        let debug_report = debug_report
            .map(|report| seal_debug_report(report, &device_public_key))
            .transpose()?;
        let result = biometrics.and_then(|biometrics| {
            build_and_seal_pcp(&state, &source_pcp, &biometrics, &device_public_key, sealer)
        });
        match result {
            Ok(pcp) => Ok(MigrateResponse { pcp, debug_report }),
            Err(error) => Err(MigrateError {
                error,
                debug_report,
            }),
        }
    })
    .await
    .map_err(|error| {
        // The unwind has already zeroized the closure's secrets; restart so the panic is seen.
        if error.is_panic() {
            tracing::error!("migration panicked");
            std::process::exit(1);
        }
        tracing::error!(%error, "migration task was cancelled");
        enclave_primitives::Error::MigrationTaskCancelled
    })?
}

fn build_and_seal_pcp(
    state: &EnclaveState,
    source_pcp: &SourcePcp,
    owned_biometrics: &OwnedPreparedBiometrics,
    device_public_key: &[u8; 32],
    sealer: ResponseSealer,
) -> Result<Vec<u8>, enclave_primitives::Error> {
    let prepared_biometrics = owned_biometrics.as_prepared();
    let migrated_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| enclave_primitives::Error::InvalidSystemTime)?
        .as_secs();
    let context = MigrationContext::new(
        TEE_SOFTWARE_VERSION.to_owned(),
        migrated_ts,
        S3Region::UsEast1,
    );

    di_migration_pcp::validate_build_inputs(
        source_pcp,
        &prepared_biometrics,
        &context,
        device_public_key,
    )
    .map_err(|error| {
        tracing::warn!(%error, "invalid biometric pipeline output for PCP build");
        enclave_primitives::Error::FailedToBuildPcp
    })?;

    let backend_keys = tokio::runtime::Handle::current()
        .block_on(BackendKeys::generate(state.key_wrapper()))
        .map_err(|error| {
            tracing::error!(%error, "failed to generate and wrap PCP backend recipients");
            enclave_primitives::Error::PcpRecipientKeyGenerationFailed
        })?;
    let recipients = backend_keys.recipients(device_public_key);
    let manifest_signer = state.manifest_signer().ok_or_else(|| {
        tracing::error!("PCP manifest signing is not configured");
        enclave_primitives::Error::ManifestSignerUnavailable
    })?;
    let package = di_migration_pcp::build(
        source_pcp,
        &prepared_biometrics,
        &context,
        recipients,
        |digest| tokio::runtime::Handle::current().block_on(manifest_signer.sign(digest)),
    )
    .map_err(|error| {
        tracing::warn!(%error, "failed to build output PCP");
        enclave_primitives::Error::FailedToBuildPcp
    })?;

    sealer.seal(&package.tier0).map_err(|error| {
        tracing::error!(?error, "failed to seal the migrated PCP");
        enclave_primitives::Error::PcpResponseSealingFailed
    })
}

fn seal_debug_report(
    report: Zeroizing<String>,
    public_key: &[u8; 32],
) -> Result<Vec<u8>, enclave_primitives::Error> {
    if report.len() > MAX_MIGRATION_DIAGNOSTIC_BYTES {
        tracing::error!(
            diagnostic_bytes = report.len(),
            "migration diagnostic exceeded its size limit"
        );
        return Err(enclave_primitives::Error::MigrationDiagnosticSealingFailed);
    }
    let mut blob = vec![0; report.len() + sealedbox::OVERHEAD_LENGTH];
    sealedbox::encrypt(report.as_bytes(), public_key, &mut blob).map_err(|error| {
        tracing::error!(?error, "failed to encrypt migration diagnostic");
        enclave_primitives::Error::MigrationDiagnosticSealingFailed
    })?;
    drop(report);
    Ok(blob)
}

fn run_pipeline(
    state: &EnclaveState,
    source_pcp: &SourcePcp,
) -> (
    Result<OwnedPreparedBiometrics, enclave_primitives::Error>,
    Option<Zeroizing<String>>,
) {
    match state.migrate(source_pcp.pipeline_inputs()) {
        Ok(mut output) => {
            let debug_report = take_debug_report(output.debug_report.take());
            (prepare_biometrics(output), debug_report)
        }
        Err(mut failure) => {
            let debug_report = take_debug_report(failure.debug_report.take().map(Zeroizing::new));
            tracing::warn!(
                ?failure,
                dependency = "worker",
                "biometric pipeline rejected migration"
            );
            let reason = pipeline_failure_reason(failure.code);
            (Err(reason), debug_report)
        }
    }
}

fn pipeline_failure_reason(code: i32) -> enclave_primitives::Error {
    use enclave_primitives::Error;

    match FailureCode::try_from(code) {
        Ok(FailureCode::InvalidRequest) => Error::BiometricInvalidRequest,
        Ok(FailureCode::InvalidImage) => Error::BiometricInvalidImage,
        Ok(FailureCode::QualityRejected) => Error::BiometricQualityRejected,
        Ok(FailureCode::SpoofDetected) => Error::BiometricSpoofDetected,
        Ok(FailureCode::Internal) => Error::BiometricPipelineFailed,
        Ok(FailureCode::Unspecified) | Err(_) => Error::Unknown,
    }
}

fn take_debug_report(report: Option<Zeroizing<String>>) -> Option<Zeroizing<String>> {
    let report = report?;
    if report.is_empty() || report.len() > MAX_MIGRATION_DIAGNOSTIC_BYTES {
        tracing::warn!(
            diagnostic_bytes = report.len(),
            dependency = "worker",
            "worker debug report has an invalid size"
        );
        return None;
    }
    if serde_json::from_str::<serde_json::Value>(&report).is_err() {
        tracing::warn!(
            dependency = "worker",
            "worker debug report is not valid JSON"
        );
        return None;
    }
    Some(report)
}

/// Owns worker iris buffers and shares so [`PreparedBiometrics`] can borrow them for PCP build.
struct OwnedPreparedBiometrics {
    pipeline_version: String,
    face_embeddings: Vec<v1::FaceEmbedding>,
    di_embeddings: v1::DiIrisEmbeddings,
    shares: [v1::DiIrisEmbeddingShares; 3],
    left_normalized: di_worker_protocol::migration::NormalizedIris,
    left_resized: di_worker_protocol::migration::NormalizedIris,
    right_normalized: di_worker_protocol::migration::NormalizedIris,
    right_resized: di_worker_protocol::migration::NormalizedIris,
}

impl OwnedPreparedBiometrics {
    fn as_prepared(&self) -> PreparedBiometrics<'_> {
        PreparedBiometrics {
            biometric_pipeline_version: self.pipeline_version.clone(),
            face_embeddings: self.face_embeddings.clone(),
            di_embeddings: self.di_embeddings.clone(),
            di_embedding_shares: self.shares.clone(),
            left_normalized: orb_pcp::NormalizedIrisFrame {
                image: &self.left_normalized.image,
                mask: &self.left_normalized.mask,
                image_resized: &self.left_resized.image,
                mask_resized: &self.left_resized.mask,
            },
            right_normalized: orb_pcp::NormalizedIrisFrame {
                image: &self.right_normalized.image,
                mask: &self.right_normalized.mask,
                image_resized: &self.right_resized.image,
                mask_resized: &self.right_resized.mask,
            },
            extra_normalized: std::collections::BTreeMap::new(),
        }
    }
}

fn prepare_biometrics(
    output: crate::worker::MigrationOutput,
) -> Result<OwnedPreparedBiometrics, enclave_primitives::Error> {
    let MigrationResult {
        face_embedding,
        left_iris,
        right_iris,
        iris_code_version: _,
        iris_model_version,
        iris_embedding_version,
        iris_inference_backend,
        debug_report: _,
    } = output.result;
    let face =
        face_embedding.ok_or(enclave_primitives::Error::IncompleteBiometricPipelineResult)?;
    let left = left_iris.ok_or(enclave_primitives::Error::IncompleteBiometricPipelineResult)?;
    let right = right_iris.ok_or(enclave_primitives::Error::IncompleteBiometricPipelineResult)?;

    let shares = generate_shares(&left, &right, &iris_model_version, &iris_embedding_version)?;

    let left_normalized = left
        .normalized
        .ok_or(enclave_primitives::Error::IncompleteBiometricPipelineResult)?;
    let left_resized = left
        .normalized_resized
        .ok_or(enclave_primitives::Error::IncompleteBiometricPipelineResult)?;
    let right_normalized = right
        .normalized
        .ok_or(enclave_primitives::Error::IncompleteBiometricPipelineResult)?;
    let right_resized = right
        .normalized_resized
        .ok_or(enclave_primitives::Error::IncompleteBiometricPipelineResult)?;

    Ok(OwnedPreparedBiometrics {
        pipeline_version: output.pipeline_version,
        face_embeddings: vec![v1::FaceEmbedding {
            embedding: Some(face.vector),
            embedding_type: Some(face.r#type),
            embedding_version: Some(face.version),
            embedding_inference_backend: Some(face.inference_backend),
        }],
        di_embeddings: v1::DiIrisEmbeddings {
            embedding_v1: Some(v1::DiIrisEmbeddingV1 {
                model_version: iris_model_version,
                embedding_inference_backend: iris_inference_backend,
                embedding_version: iris_embedding_version,
                left_embedding: signed_embedding(&left.embedding),
                left_mirror_embedding: signed_embedding(&left.mirror_embedding),
                right_embedding: signed_embedding(&right.embedding),
                right_mirror_embedding: signed_embedding(&right.mirror_embedding),
                left_embedding_f32: left.embedding_f32,
                left_mirror_embedding_f32: left.mirror_embedding_f32,
                right_embedding_f32: right.embedding_f32,
                right_mirror_embedding_f32: right.mirror_embedding_f32,
            }),
        },
        shares,
        left_normalized,
        left_resized,
        right_normalized,
        right_resized,
    })
}

fn signed_embedding(embedding: &[u8]) -> Vec<i32> {
    embedding
        .iter()
        .map(|byte| i32::from(byte.cast_signed()))
        .collect()
}

fn generate_shares(
    left: &di_worker_protocol::migration::EyeResult,
    right: &di_worker_protocol::migration::EyeResult,
    model_version: &str,
    embedding_version: &str,
) -> Result<[v1::DiIrisEmbeddingShares; 3], enclave_primitives::Error> {
    let mut rng = OsRng;
    let left_shares = di_migration_shares::generate(&left.embedding, &mut rng);
    let left_mirror_shares = di_migration_shares::generate(&left.mirror_embedding, &mut rng);
    let right_shares = di_migration_shares::generate(&right.embedding, &mut rng);
    let right_mirror_shares = di_migration_shares::generate(&right.mirror_embedding, &mut rng);
    let [
        left_shares,
        left_mirror_shares,
        right_shares,
        right_mirror_shares,
    ] = [
        left_shares,
        left_mirror_shares,
        right_shares,
        right_mirror_shares,
    ]
    .map(|shares| {
        shares.map_err(|error| {
            tracing::error!(%error, "failed to generate DI embedding shares");
            enclave_primitives::Error::EmbeddingShareGenerationFailed
        })
    });
    let left_shares = left_shares?;
    let left_mirror_shares = left_mirror_shares?;
    let right_shares = right_shares?;
    let right_mirror_shares = right_mirror_shares?;

    let shares = std::array::from_fn(|recipient| v1::DiIrisEmbeddingShares {
        share_v1: Some(v1::DiIrisEmbeddingShareV1 {
            model_version: model_version.to_owned(),
            shares_version: di_migration_shares::VERSION.to_owned(),
            embedding_version: embedding_version.to_owned(),
            left_share: left_shares[recipient]
                .iter()
                .copied()
                .map(u32::from)
                .collect(),
            left_mirror_share: left_mirror_shares[recipient]
                .iter()
                .copied()
                .map(u32::from)
                .collect(),
            right_share: right_shares[recipient]
                .iter()
                .copied()
                .map(u32::from)
                .collect(),
            right_mirror_share: right_mirror_shares[recipient]
                .iter()
                .copied()
                .map(u32::from)
                .collect(),
        }),
    });
    Ok(shares)
}

fn parse_source_pcp(
    state: &EnclaveState,
    files: di_migration_pcp::Files,
) -> Result<SourcePcp, enclave_primitives::Error> {
    let parsed =
        tokio::runtime::Handle::current().block_on(SourcePcp::parse(files, state.key_wrapper()));
    parsed.map_err(|error| {
        if matches!(error, di_migration_pcp::Error::BackendKeyDecryption(_)) {
            tracing::error!(%error, dependency = "kms", "source PCP key unwrap failed");
            enclave_primitives::Error::PcpKeyDecryptionFailed
        } else {
            tracing::warn!(%error, "migrate request PCP could not be parsed");
            enclave_primitives::Error::InvalidPcp
        }
    })
}

/// Checks the credential's subject, issuer signature, and PCP `hashes.json` claim.
fn verify_credential(
    issuer_pubkey: &EdDSAPublicKey,
    expected_sub: &str,
    credential_json: &str,
    pcp: &[u8],
) -> Result<(), enclave_primitives::Error> {
    let credential: Credential =
        serde_json::from_slice(credential_json.as_bytes()).map_err(|error| {
            tracing::warn!(%error, "failed to deserialize credential");
            enclave_primitives::Error::CredentialDeserializationFailed
        })?;
    if credential.sub.to_string() != expected_sub {
        tracing::warn!("credential sub mismatch");
        return Err(enclave_primitives::Error::CredentialSubMismatch);
    }

    let valid = credential
        .verify_signature(issuer_pubkey)
        .map_err(|error| {
            tracing::warn!(%error, "credential signature verification failed");
            enclave_primitives::Error::CredentialSignatureVerificationFailed
        })?;
    if !valid {
        tracing::warn!("credential signature is invalid");
        return Err(enclave_primitives::Error::CredentialSignatureInvalid);
    }

    // claims[0] is Poseidon2(CLAIMS_HASH_V1, raw hashes.json) for a PCP-backed credential.
    let hashes_json = hashes_json_from_pcp(pcp)?;
    let expected_claim =
        hash_bytes_to_field_element(ds::CLAIMS_HASH_V1, &hashes_json).map_err(|_| {
            tracing::warn!("failed to hash hashes.json into a claim");
            enclave_primitives::Error::CredentialClaimsMismatch
        })?;
    let Some(actual_claim) = credential.claims.first() else {
        tracing::warn!("credential carried no claims");
        return Err(enclave_primitives::Error::CredentialClaimsMismatch);
    };
    if expected_claim != *actual_claim {
        tracing::warn!("credential claims mismatch");
        return Err(enclave_primitives::Error::CredentialClaimsMismatch);
    }
    Ok(())
}

/// Reads `hashes.json` from a gzip-compressed tar PCP without writing to disk.
fn hashes_json_from_pcp(pcp: &[u8]) -> Result<Vec<u8>, enclave_primitives::Error> {
    let mut archive = Archive::new(GzDecoder::new(pcp));
    let entries = archive.entries().map_err(|error| {
        tracing::warn!(%error, "PCP is not a gzip tar archive");
        enclave_primitives::Error::InvalidInput
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            tracing::warn!(%error, "failed to read a PCP tar entry");
            enclave_primitives::Error::InvalidInput
        })?;
        let is_hashes = entry
            .path()
            .map(|path| path.as_ref() == Path::new("hashes.json"))
            .map_err(|error| {
                tracing::warn!(%error, "PCP tar entry path is invalid");
                enclave_primitives::Error::InvalidInput
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
                enclave_primitives::Error::InvalidInput
            })?;
        if hashes_json.is_empty() || hashes_json.len() > MAX_HASHES_JSON_BYTES {
            tracing::warn!("hashes.json missing or too large");
            return Err(enclave_primitives::Error::InvalidInput);
        }
        return Ok(hashes_json);
    }

    tracing::warn!("PCP did not contain hashes.json");
    Err(enclave_primitives::Error::InvalidInput)
}

#[cfg(test)]
mod tests {
    use std::{io::Write, sync::Arc};

    use di_migration_enclave_primitives::{
        self as enclave_primitives, MIGRATION_CHANNEL_DOMAIN, MigrateRequest, pcp_payload,
    };
    use di_worker_protocol::migration::{
        EMBEDDING_SIZE, EyeResult, FaceEmbedding, MigrationResult, NormalizedIris,
    };
    use flate2::write::GzEncoder;
    use pontifex::channel::{ChannelConsumer, ChannelDomain, ResponseOpener};
    use world_id_primitives::{Credential, EdDSAPrivateKey, FieldElement};

    use super::{handler, prepare_biometrics, seal_debug_report, take_debug_report};
    use crate::{state::EnclaveState, test_support, worker::MigrationOutput};
    use zeroize::Zeroizing;

    fn eye(embedding: u8, mirror_embedding: u8) -> EyeResult {
        EyeResult {
            embedding: vec![embedding; EMBEDDING_SIZE],
            mirror_embedding: vec![mirror_embedding; EMBEDDING_SIZE],
            embedding_f32: vec![0.25; EMBEDDING_SIZE],
            mirror_embedding_f32: vec![-0.25; EMBEDDING_SIZE],
            normalized: Some(NormalizedIris {
                image: vec![1],
                mask: vec![2],
            }),
            normalized_resized: Some(NormalizedIris {
                image: vec![3],
                mask: vec![4],
            }),
            ..EyeResult::default()
        }
    }

    #[test]
    fn pipeline_result_is_mapped_to_pcp_biometrics_and_fresh_shares() {
        let output = MigrationOutput {
            pipeline_version: "worker-release".into(),
            debug_report: Some(Zeroizing::new(r#"{"stage":"completed"}"#.into())),
            result: MigrationResult {
                face_embedding: Some(FaceEmbedding {
                    vector: "face-vector".into(),
                    r#type: "face".into(),
                    version: "2".into(),
                    inference_backend: "cpu".into(),
                }),
                left_iris: Some(eye((-8_i8).cast_unsigned(), 7)),
                right_iris: Some(eye(6, (-7_i8).cast_unsigned())),
                iris_model_version: "di-model".into(),
                iris_embedding_version: "di-embedding".into(),
                iris_inference_backend: "cpu".into(),
                ..MigrationResult::default()
            },
        };

        let mapped = prepare_biometrics(output).expect("valid worker result should map");
        let prepared = mapped.as_prepared();
        let embedding = prepared
            .di_embeddings
            .embedding_v1
            .as_ref()
            .expect("DI embedding");

        assert_eq!(prepared.biometric_pipeline_version, "worker-release");
        assert_eq!(embedding.left_embedding, vec![-8; EMBEDDING_SIZE]);
        assert_eq!(embedding.right_mirror_embedding, vec![-7; EMBEDDING_SIZE]);
        for share in prepared.di_embedding_shares {
            let share = share.share_v1.expect("versioned share");
            assert_eq!(share.shares_version, di_migration_shares::VERSION);
            assert_eq!(share.left_share.len(), EMBEDDING_SIZE);
            assert_eq!(share.right_mirror_share.len(), EMBEDDING_SIZE);
        }
        assert_eq!(prepared.left_normalized.image, &[1]);
        assert_eq!(prepared.right_normalized.mask_resized, &[4]);
    }

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
            handler(state, request).await,
            Err(enclave_primitives::Error::InvalidPcp.into())
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
            handler(state, request).await,
            Err(enclave_primitives::Error::CredentialSignatureInvalid.into())
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
            handler(state, request).await,
            Err(enclave_primitives::Error::CredentialSignatureVerificationFailed.into())
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
            .expect_err("a new boot cannot open it");

        assert_eq!(error, enclave_primitives::Error::RequestNotOpened.into());
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
                Err(enclave_primitives::Error::InvalidInput.into())
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
                handler(Arc::clone(&state), request).await,
                Err(enclave_primitives::Error::InvalidInput.into())
            );
        }
    }

    #[test]
    fn only_actual_worker_debug_reports_are_sealed() {
        use alkali::asymmetric::seal::curve25519xsalsa20poly1305 as sealedbox;

        let pair = sealedbox::Keypair::generate().unwrap();
        for report in [None, Some("not json"), Some(r#"{"stage":"face"}"#)] {
            let debug_report =
                take_debug_report(report.map(|report| Zeroizing::new(report.to_owned())));
            if let Some(debug_report) = debug_report {
                let mut plaintext = Zeroizing::new(vec![0; debug_report.len()]);
                let blob = seal_debug_report(debug_report, &pair.public_key).expect("seal report");
                sealedbox::decrypt(&blob, &pair, &mut plaintext).unwrap();
                assert_eq!(
                    plaintext.as_slice(),
                    report.expect("valid report").as_bytes()
                );
            }
        }
    }
}
