use crate::source::{legacy_artifact, raw_image};
use crate::{BackendKeys, Error, Files, Info, Migration, PipelineMetadata, SourcePcp};

/// Values supplied by the trusted TEE orchestration layer, never by the sandbox.
pub struct MigrationContext {
    pub tee_version: String,
    pub migrated_ts: u64,
}

/// Prepared inference output and shares, in the shared builder's
/// native types. There is no second implementation of the payload serializers,
/// commitments, archive layout, hashing, signing or encryption in this crate.
///
/// The sandbox adapter must validate model-specific dimensions and encodings;
/// the sharing stage must bind every share to these exact outputs. This mapper
/// checks availability and cross-output version consistency before assembly.
pub struct PreparedBiometrics<'a> {
    pub metadata: PipelineMetadata,
    pub face_embeddings: Vec<orb_pcp::FaceEmbedding<'a>>,
    pub daugman: orb_pcp::DaugmanData<'a>,
    pub di: orb_pcp::DiData<'a>,
    pub left_normalized: orb_pcp::NormalizedIrisFrame<'a>,
    pub right_normalized: orb_pcp::NormalizedIrisFrame<'a>,
    /// Fresh normalization keyed by source multiframe image ID.
    pub extra_normalized: std::collections::BTreeMap<String, orb_pcp::NormalizedIrisFrame<'a>>,
}

impl PreparedBiometrics<'_> {
    fn validate(&self, source: &SourcePcp) -> Result<(), Error> {
        // These upper bounds are local resource guards, not model dimensions.
        for (name, value) in [
            (
                "biometric_pipeline_version",
                self.metadata.biometric_pipeline_version.as_str(),
            ),
            ("di_model_version", self.metadata.di_model_version.as_str()),
            ("iris_version", self.metadata.iris_version.as_str()),
            (
                "di_inference_backend",
                self.metadata.di_inference_backend.as_str(),
            ),
            ("iris_shares_version", self.daugman.shares_version),
            ("di_shares_version", self.di.shares_version),
            ("di_embedding_version", self.di.embedding_version),
        ] {
            nonempty(value, name)?;
        }
        if self.di.model_version != self.metadata.di_model_version
            || self.di.inference_backend != self.metadata.di_inference_backend
            || self.daugman.iris_version != Some(self.metadata.iris_version.as_str())
        {
            return Err(Error::MetadataMismatch);
        }
        if self.face_embeddings.is_empty() || self.face_embeddings.len() > 16 {
            return Err(Error::InvalidField("face_embeddings"));
        }
        for face in &self.face_embeddings {
            nonempty(face.embedding, "face_embedding")?;
            nonempty(face.embedding_type, "face_embedding_type")?;
            nonempty(face.embedding_version, "face_embedding_version")?;
            nonempty(
                face.embedding_inference_backend,
                "face_embedding_inference_backend",
            )?;
        }
        for eye in [&self.daugman.left, &self.daugman.right] {
            required_text(eye.iris_code, "iris_code")?;
            required_text(eye.mask_code, "mask_code")?;
            for share in eye.iris_code_shares.into_iter().chain(eye.mask_code_shares) {
                nonempty(share, "iris_code_share")?;
            }
        }
        for eye in [self.di.left.as_ref(), self.di.right.as_ref()] {
            let eye = eye.ok_or(Error::InvalidField("di_eye"))?;
            let n = eye.embedding.len();
            if n == 0
                || n > 65536
                || eye.mirror_embedding.len() != n
                || eye.embedding_f32.len() != n
                || eye.mirror_embedding_f32.len() != n
                || eye
                    .embedding_f32
                    .iter()
                    .chain(eye.mirror_embedding_f32)
                    .any(|v| !v.is_finite())
                || eye
                    .embedding_shares
                    .iter()
                    .chain(&eye.mirror_embedding_shares)
                    .any(|s| s.len() != n)
            {
                return Err(Error::InvalidField("di_eye"));
            }
        }
        if self.extra_normalized.len() > 512 {
            return Err(Error::SizeLimit);
        }
        for id in self.extra_normalized.keys() {
            let referenced = source
                .info
                .left_ir_multiframe_image_ids
                .as_deref()
                .unwrap_or_default()
                .iter()
                .chain(
                    source
                        .info
                        .right_ir_multiframe_image_ids
                        .as_deref()
                        .unwrap_or_default(),
                )
                .any(|source_id| source_id == id);
            if !referenced
                || source
                    .files
                    .get(&format!("iris/{id}.png"))
                    .is_none_or(Vec::is_empty)
            {
                return Err(Error::InvalidField("normalized_image_id"));
            }
        }
        for normalized in [&self.left_normalized, &self.right_normalized]
            .into_iter()
            .chain(self.extra_normalized.values())
        {
            for data in [
                normalized.image,
                normalized.mask,
                normalized.image_resized,
                normalized.mask_resized,
            ] {
                if data.is_empty() || data.len() > 16 * 1024 * 1024 {
                    return Err(Error::InvalidField("normalized_iris"));
                }
            }
        }
        Ok(())
    }
}

/// PCP v2.9 content for assembly by the shared builder.
/// `None` represents unavailable metadata.
pub struct MappedPcp<'a> {
    pub info: Info,
    /// Source envelopes for migration/diagnostics, not automatically authorized
    /// encryption recipients for the new package. New keys come from the caller.
    pub source_backend_keys: Option<BackendKeys>,
    pub migration: Migration,
    pub raw_images: Files,
    /// Relative file names inside `legacy/`. Bytes are exact.
    pub legacy: Files,
    pub biometrics: PreparedBiometrics<'a>,
}

impl MappedPcp<'_> {
    pub const VERSION: &'static str = "2.9";
}

/// Map one authenticated, opened source and one successful pipeline execution.
/// Source versions lacking a required image remain inspectable via `SourcePcp`,
/// but cannot produce mapped output. Retain `source` until the
/// final `verify_preserved_data` check of the assembled output has passed.
pub fn migrate<'a>(
    source: &SourcePcp,
    biometrics: PreparedBiometrics<'a>,
    context: MigrationContext,
) -> Result<MappedPcp<'a>, Error> {
    source.pipeline_inputs()?;
    crate::source::required(&source.files, "hashes.sign")?;
    biometrics.validate(source)?;
    nonempty(&context.tee_version, "tee_version")?;
    let old_signup_id = required_text(source.info.signup_id.as_deref(), "signup_id")?.to_owned();
    let new_signup_id =
        generate_migration_signup_id(&old_signup_id, &biometrics.metadata.di_model_version)?;
    let migration = Migration {
        tee_version: Some(context.tee_version),
        src_signup_id: Some(old_signup_id),
        source_pcp_version: Some(source.version.as_str().to_owned()),
        migrated_ts: Some(context.migrated_ts),
        biometric_pipeline_version: Some(biometrics.metadata.biometric_pipeline_version.clone()),
    };
    let mut info = source.info.clone();
    info.src_signup_id.clone_from(&source.info.signup_id);
    info.signup_id = Some(new_signup_id);
    info.signup_id_salt = None; // Builder generates a salt for the changed identity.
    let mut raw_images = Files::new();
    let mut legacy = Files::new();
    for (path, bytes) in &source.files {
        if raw_image(path) {
            raw_images.insert(path.clone(), bytes.clone());
        } else if legacy_artifact(path) {
            legacy.insert(path.clone(), bytes.clone());
        }
    }
    crate::preservation::verify_artifacts(source, &raw_images, &legacy)?;
    Ok(MappedPcp {
        info,
        source_backend_keys: source.backend_keys.clone(),
        migration,
        raw_images,
        legacy,
        biometrics,
    })
}

/// Identity rule for supported original Orb sources (through v2.8).
/// Naming is not signup registration or ownership authorization.
pub fn generate_migration_signup_id(
    src_signup_id: &str,
    di_model_version: &str,
) -> Result<String, Error> {
    for (value, name) in [
        (src_signup_id, "src_signup_id"),
        (di_model_version, "di_model_version"),
    ] {
        nonempty(value, name)?;
        if value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(Error::InvalidField(name));
        }
    }
    Ok(format!("{src_signup_id}_di_v{di_model_version}"))
}

fn nonempty(value: &str, field: &'static str) -> Result<(), Error> {
    if value.is_empty() || value.len() > 1024 * 1024 {
        Err(Error::InvalidField(field))
    } else {
        Ok(())
    }
}

fn required_text<'a>(value: Option<&'a str>, field: &'static str) -> Result<&'a str, Error> {
    let value = value.ok_or(Error::InvalidField(field))?;
    nonempty(value, field)?;
    Ok(value)
}
