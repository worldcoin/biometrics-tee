use std::{
    io::Read,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::pcp_keys::BackendKeys;
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

use crate::{
    debug_report::{Report, Stage},
    state::EnclaveState,
};

/// Ceiling for `hashes.json` inside a PCP; the file is a small JSON manifest.
const MAX_HASHES_JSON_BYTES: usize = 1024 * 1024;
const TEE_SOFTWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Unseals the app's PCP with this boot's key and seals it back to the app's one-time response
/// key, so the host only ever handles ciphertext. The PCP tiers are encrypted to the
/// device public key inside the client's sealed payload.
pub async fn handler(
    state: Arc<EnclaveState>,
    request: MigrateRequest,
) -> Result<MigrateResponse, MigrateError> {
    let started = SystemTime::now();
    if request.blob.is_empty() {
        tracing::warn!("migrate request carried no blob");
        return Err(enclave_primitives::Error::InvalidInput.into());
    }

    // Unsealing and sealing are CPU-bound; keep them off the async workers.
    tokio::task::spawn_blocking(move || -> Result<MigrateResponse, MigrateError> {
        let (plaintext, sealer) = state.channel().open(&request.blob).map_err(|error| {
            tracing::warn!(?error, "migrate request was not sealed to this boot");
            enclave_primitives::Error::RequestNotOpened
        })?;
        let mut report = Report::new(started);
        let result = migrate_payload(&state, &plaintext, &request.sub, sealer, &mut report);
        drop(plaintext);
        let error = result.as_ref().err().copied();
        finish_migration(result, || {
            report.serialize(&state, error).and_then(|report| {
                // Pontifex consumes each sealer. Unseal the same authenticated request again
                // to seal the report separately to the same response key.
                let (_, report_sealer) = state
                    .channel()
                    .open(&request.blob)
                    .inspect_err(|_| {
                        tracing::warn!("failed to recover the diagnostic response sealer");
                    })
                    .ok()?;
                // Diagnostic failure preserves the already established migration outcome.
                seal_debug_report(report, report_sealer).ok()
            })
        })
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

fn finish_migration(
    result: Result<Vec<u8>, enclave_primitives::Error>,
    produce_report: impl FnOnce() -> Option<Vec<u8>>,
) -> Result<MigrateResponse, MigrateError> {
    // Reporting only reads enclave state and owns its temporary buffers. Unwinding it
    // cannot invalidate the completed migration or the biometric worker's state.
    let debug_report = catch_unwind(AssertUnwindSafe(produce_report)).unwrap_or_else(|_| {
        tracing::error!("debug report production panicked; preserving migration outcome");
        None
    });
    match result {
        Ok(pcp) => Ok(MigrateResponse { pcp, debug_report }),
        Err(error) => Err(MigrateError {
            error,
            debug_report,
        }),
    }
}

fn migrate_payload(
    state: &EnclaveState,
    plaintext: &[u8],
    sub: &str,
    sealer: ResponseSealer,
    report: &mut Report,
) -> Result<Vec<u8>, enclave_primitives::Error> {
    let payload = pcp_payload::decode(plaintext).inspect_err(|_| {
        tracing::warn!("migrate request carried an unknown payload");
    })?;
    report.stage = Stage::VerifyCredential;
    verify_credential(
        state.issuer_pubkey(),
        sub,
        &payload.credential,
        &payload.pcp,
    )?;
    report.stage = Stage::OpenPcp;
    let files = di_migration_pcp::files_from_tar_gz(&payload.pcp).map_err(|error| {
        tracing::warn!(%error, "migrate request PCP archive could not be opened");
        enclave_primitives::Error::InvalidPcp
    })?;
    let source_pcp = parse_source_pcp(state, files)?;
    report.source(&source_pcp);
    let biometrics = run_pipeline(state, &source_pcp, report)?;
    build_and_seal_pcp(
        state,
        &source_pcp,
        &biometrics,
        &payload.device_public_key,
        sealer,
        report,
    )
}

fn build_and_seal_pcp(
    state: &EnclaveState,
    source_pcp: &SourcePcp,
    owned_biometrics: &OwnedPreparedBiometrics,
    device_public_key: &[u8; 32],
    sealer: ResponseSealer,
    report: &mut Report,
) -> Result<Vec<u8>, enclave_primitives::Error> {
    report.stage = Stage::BuildPcp;
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
    report.signup_id = Some(context.signup_id.clone());

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

    report.stage = Stage::GenerateRecipients;
    let backend_keys = tokio::runtime::Handle::current()
        .block_on(BackendKeys::generate(state.key_wrapper()))
        .map_err(|error| {
            tracing::error!(%error, "failed to generate and wrap PCP backend recipients");
            enclave_primitives::Error::PcpRecipientKeyGenerationFailed
        })?;
    let recipients = backend_keys.recipients(device_public_key);
    report.stage = Stage::SignManifest;
    let manifest_signer = state.manifest_signer().ok_or_else(|| {
        tracing::error!("PCP manifest signing is not configured");
        enclave_primitives::Error::ManifestSignerUnavailable
    })?;
    report.stage = Stage::BuildPcp;
    let package = di_migration_pcp::build(
        source_pcp,
        &prepared_biometrics,
        &context,
        recipients,
        |digest| {
            report.stage = Stage::SignManifest;
            let result = tokio::runtime::Handle::current().block_on(manifest_signer.sign(digest));
            if result.is_ok() {
                report.stage = Stage::BuildPcp;
            }
            result
        },
    )
    .map_err(|error| {
        tracing::warn!(%error, "failed to build output PCP");
        enclave_primitives::Error::FailedToBuildPcp
    })?;

    report.stage = Stage::SealPcp;
    sealer.seal(&package.tier0).map_err(|error| {
        tracing::error!(?error, "failed to seal the migrated PCP");
        enclave_primitives::Error::PcpResponseSealingFailed
    })
}

fn seal_debug_report(
    report: Zeroizing<String>,
    sealer: ResponseSealer,
) -> Result<Vec<u8>, enclave_primitives::Error> {
    if report.len() > MAX_MIGRATION_DIAGNOSTIC_BYTES {
        tracing::error!(
            diagnostic_bytes = report.len(),
            "migration diagnostic exceeded its size limit"
        );
        return Err(enclave_primitives::Error::MigrationDiagnosticSealingFailed);
    }
    let blob = sealer.seal(report.as_bytes()).map_err(|error| {
        tracing::error!(?error, "failed to seal migration diagnostic");
        enclave_primitives::Error::MigrationDiagnosticSealingFailed
    })?;
    drop(report);
    Ok(blob)
}

fn run_pipeline(
    state: &EnclaveState,
    source_pcp: &SourcePcp,
    report: &mut Report,
) -> Result<OwnedPreparedBiometrics, enclave_primitives::Error> {
    report.stage = Stage::Biometrics;
    match state.migrate(source_pcp.pipeline_inputs()) {
        Ok(mut output) => {
            report.worker_report(output.debug_report.take());
            report.stage = Stage::PrepareBiometrics;
            prepare_biometrics(output)
        }
        Err(mut failure) => {
            report.worker_report(failure.debug_report.take().map(Zeroizing::new));
            report.worker_failure(&failure);
            tracing::warn!(
                ?failure,
                dependency = "worker",
                "biometric pipeline rejected migration"
            );
            let reason = pipeline_failure_reason(failure.code);
            Err(reason)
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

    use super::{finish_migration, handler, prepare_biometrics, seal_debug_report};
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
        let payload = pcp_payload::encode(&pcp, &credential, &[7; 32]).expect("encode");

        let (request, opener) = sealed(&state, &payload, sub.to_string());
        let failure = handler(state, request).await.unwrap_err();
        assert_eq!(failure.error, enclave_primitives::Error::InvalidPcp);
        let report = opener
            .open_from_enclave(&failure.debug_report.unwrap())
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&report).unwrap();
        assert_eq!(report["metadata"]["signup_status"], "Failure");
        assert_eq!(
            report["pipeline_errors"]["migration_error"]["stage"],
            "open_pcp"
        );
        assert!(report["signup_id"].is_null());
        assert!(report["src_signup_id"].is_null());
        assert!(report["face"].is_null());
        assert!(report["iris"].is_null());
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
        let payload = pcp_payload::encode(&pcp, &credential.to_string(), &[7; 32]).expect("encode");
        let (request, opener) = sealed(&state, &payload, sub.to_string());
        let failure = handler(state, request).await.unwrap_err();
        assert_eq!(
            failure.error,
            enclave_primitives::Error::CredentialSignatureInvalid
        );
        let plaintext = opener
            .open_from_enclave(&failure.debug_report.unwrap())
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(
            report["pipeline_errors"]["migration_error"]["stage"],
            "verify_credential"
        );
        assert!(report["face"].is_null());
        assert!(!String::from_utf8_lossy(&plaintext).contains("issuer_version"));
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
        let payload = pcp_payload::encode(&pcp, &credential, &[7; 32]).expect("encode");
        let (request, _) = sealed(&state, &payload, sub.to_string());

        let failure = handler(state, request).await.unwrap_err();
        assert_eq!(
            failure.error,
            enclave_primitives::Error::CredentialSignatureVerificationFailed
        );
        assert!(failure.debug_report.is_some());
    }

    #[tokio::test]
    async fn a_blob_sealed_to_another_boot_is_not_opened() {
        let earlier = test_support::state();
        let (request, _) = sealed(
            &earlier,
            &pcp_payload::encode(b"old pcp", "self-custody", &[7; 32]).expect("encode"),
            "sub",
        );

        let error = handler(Arc::new(test_support::state()), request)
            .await
            .expect_err("a new boot cannot open it");

        assert_eq!(error, enclave_primitives::Error::RequestNotOpened.into());
    }

    #[tokio::test]
    async fn the_host_cannot_substitute_the_sealed_recipient_key() {
        let issuer = EdDSAPrivateKey::from_bytes([7; 32]);
        let state = Arc::new(test_support::state_with_issuer_pubkey(issuer.public()));
        let hashes_json = br#"{"thumbnail.png":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        let pcp = pcp_with_hashes_json(hashes_json);
        let sub = FieldElement::from(42u64);
        let credential = signed_credential_for_pcp(&issuer, hashes_json, sub);
        let payload = pcp_payload::encode(&pcp, &credential, &[7; 32]).unwrap();
        let (request, _) = sealed(&state, &payload, sub.to_string());

        // The recipient is supplied only inside the sealed payload.
        let mut forwarded = serde_json::to_value(&request).unwrap();
        assert!(forwarded.get("device_public_key").is_none());
        let matching = handler(Arc::clone(&state), request.clone())
            .await
            .unwrap_err();
        assert_eq!(matching.error, enclave_primitives::Error::InvalidPcp);

        // An obsolete outer key is ignored and cannot change the sealed recipient.
        forwarded["device_public_key"] = serde_json::json!(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [8; 32],
        ));
        let substituted = handler(state, serde_json::from_value(forwarded).unwrap())
            .await
            .unwrap_err();
        assert_eq!(substituted.error, enclave_primitives::Error::InvalidPcp);
        assert!(substituted.debug_report.is_some());
    }

    #[tokio::test]
    async fn an_unknown_payload_or_empty_blob_is_invalid() {
        let state = Arc::new(test_support::state());
        let (unknown, opener) = sealed(&state, &[9, 1, 2], "sub");
        let mut empty = unknown.clone();
        empty.blob = Vec::new().into();

        let failure = handler(Arc::clone(&state), unknown).await.unwrap_err();
        assert_eq!(failure.error, enclave_primitives::Error::InvalidInput);
        let plaintext = opener
            .open_from_enclave(&failure.debug_report.unwrap())
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(
            report["pipeline_errors"]["migration_error"]["stage"],
            "decode_payload"
        );
        let failure = handler(state, empty).await.unwrap_err();
        assert_eq!(failure.error, enclave_primitives::Error::InvalidInput);
        assert!(failure.debug_report.is_none());
    }

    #[test]
    fn report_failures_and_panics_preserve_the_completed_migration() {
        let producers: [fn() -> Option<Vec<u8>>; 2] =
            [|| None, || panic!("injected diagnostic panic")];
        for produce_report in producers {
            for result in [
                Ok(b"sealed PCP".to_vec()),
                Err(enclave_primitives::Error::FailedToBuildPcp),
            ] {
                let actual = finish_migration(result.clone(), produce_report);
                match (result, actual) {
                    (Ok(expected), Ok(response)) => {
                        assert_eq!(response.pcp, expected);
                        assert!(response.debug_report.is_none());
                    }
                    (Err(expected), Err(failure)) => {
                        assert_eq!(failure.error, expected);
                        assert!(failure.debug_report.is_none());
                    }
                    _ => panic!("diagnostics changed the migration outcome"),
                }
            }
        }
        assert!(finish_migration(Ok(vec![1]), || Some(vec![2])).is_ok());
    }

    #[test]
    fn report_encryption_preserves_bytes_and_enforces_the_size_limit() {
        let state = test_support::state();
        let maximum_report = format!(
            r#"{{"detail":"{}"}}"#,
            "x".repeat(
                enclave_primitives::MAX_MIGRATION_DIAGNOSTIC_BYTES - r#"{"detail":""}"#.len()
            )
        );
        let oversized_report = format!("{maximum_report} ");
        for (report, expected) in [
            (r#"{"face":null}"#, true),
            (maximum_report.as_str(), true),
            (oversized_report.as_str(), false),
        ] {
            let (request, opener) = sealed(&state, b"request", "sub");
            let (_, sealer) = state.channel().open(&request.blob).unwrap();
            let result = seal_debug_report(Zeroizing::new(report.to_owned()), sealer);
            assert_eq!(result.is_ok(), expected);
            if let Ok(blob) = result {
                assert_eq!(
                    blob.len(),
                    report.len() + enclave_primitives::MIGRATION_DIAGNOSTIC_OVERHEAD_BYTES
                );
                let plaintext = opener.open_from_enclave(&blob).unwrap();
                assert_eq!(plaintext.as_slice(), report.as_bytes());
            }
        }
    }
}
