use crate::{Error, SourcePcp};

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
/// the sharing stage must bind every share to these exact outputs.
/// `with_build_request` checks availability and consistency before building.
pub struct PreparedBiometrics<'a> {
    /// Release version of the executed biometric pipeline, recorded in `migration.pb`.
    pub biometric_pipeline_version: String,
    pub face_embeddings: Vec<orb_pcp::FaceEmbedding<'a>>,
    pub daugman: orb_pcp::DaugmanData<'a>,
    pub di: orb_pcp::DiData<'a>,
    pub left_normalized: orb_pcp::NormalizedIrisFrame<'a>,
    pub right_normalized: orb_pcp::NormalizedIrisFrame<'a>,
    /// Fresh normalization keyed by source multiframe image ID.
    pub extra_normalized: std::collections::BTreeMap<String, orb_pcp::NormalizedIrisFrame<'a>>,
}

impl PreparedBiometrics<'_> {
    pub(crate) fn validate(&self, source: &SourcePcp) -> Result<(), Error> {
        // These upper bounds are local resource guards, not model dimensions.
        // `di.model_version` is checked when deriving the signup ID.
        for (name, value) in [
            (
                "biometric_pipeline_version",
                self.biometric_pipeline_version.as_str(),
            ),
            ("di_inference_backend", self.di.inference_backend),
            ("iris_shares_version", self.daugman.shares_version),
            ("di_shares_version", self.di.shares_version),
            ("di_embedding_version", self.di.embedding_version),
        ] {
            nonempty(value, name)?;
        }
        required_text(self.daugman.iris_version, "iris_version")?;
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

/// The source signup ID and the new one derived from it and the DI model version.
pub(crate) fn signup_ids<'a>(
    source: &'a SourcePcp,
    biometrics: &PreparedBiometrics<'_>,
) -> Result<(&'a str, String), Error> {
    let source_signup_id = required_text(source.info.signup_id.as_deref(), "signup_id")?;
    let signup_id = generate_migration_signup_id(source_signup_id, biometrics.di.model_version)?;
    Ok((source_signup_id, signup_id))
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
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(Error::InvalidField(name));
        }
    }
    Ok(format!("{src_signup_id}_di_v{di_model_version}"))
}

pub(crate) fn nonempty(value: &str, field: &'static str) -> Result<(), Error> {
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
