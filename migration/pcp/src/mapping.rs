use std::collections::BTreeMap;

use orb_pcp_defs::v1;
use orb_wld_data_id::{S3Region, SignupId};

use crate::{Error, SourcePcp};

/// Values supplied by the trusted TEE orchestration layer, never by the sandbox.
pub struct MigrationContext {
    /// Release version of the TEE software, recorded in `migration.pb`.
    pub tee_software_version: String,
    /// Unix seconds; also the archive header time, so it must fit in 32 bits.
    pub migrated_ts: u64,
    /// The new package's signup ID. The build and the final check use this value.
    pub signup_id: SignupId,
}

impl MigrationContext {
    /// Context for one run, with a new random signup ID for `s3_region`, the
    /// region of this deployment.
    pub fn new(tee_software_version: String, migrated_ts: u64, s3_region: S3Region) -> Self {
        Self {
            tee_software_version,
            migrated_ts,
            signup_id: SignupId::new(s3_region),
        }
    }
}

/// This run's pipeline outputs and shares, as the shared builder takes them.
/// The builder encodes them; this crate has no second payload encoder.
///
/// The sandbox adapter must validate model-specific dimensions and encodings;
/// the sharing stage must bind every share to these exact outputs.
/// `with_build_request` checks availability and consistency before building.
pub struct PreparedBiometrics<'a> {
    /// Release version of the executed biometric pipeline, recorded in `migration.pb`.
    pub biometric_pipeline_version: String,
    pub face_embeddings: Vec<v1::FaceEmbedding>,
    pub di_embeddings: v1::DiIrisEmbeddings,
    /// Index `i` belongs to recipient `i`.
    pub di_embedding_shares: [v1::DiIrisEmbeddingShares; 3],
    pub left_normalized: orb_pcp::NormalizedIrisFrame<'a>,
    pub right_normalized: orb_pcp::NormalizedIrisFrame<'a>,
    /// Fresh normalization keyed by source multiframe image ID.
    pub extra_normalized: BTreeMap<String, orb_pcp::NormalizedIrisFrame<'a>>,
}

impl PreparedBiometrics<'_> {
    pub(crate) fn validate(&self, source: &SourcePcp) -> Result<(), Error> {
        // These upper bounds are local resource guards, not model dimensions.
        nonempty(
            &self.biometric_pipeline_version,
            "biometric_pipeline_version",
        )?;
        if self.face_embeddings.is_empty() || self.face_embeddings.len() > 16 {
            return Err(Error::InvalidField("face_embeddings"));
        }
        for face in &self.face_embeddings {
            for (value, field) in [
                (&face.embedding, "face_embedding"),
                (&face.embedding_type, "face_embedding_type"),
                (&face.embedding_version, "face_embedding_version"),
                (
                    &face.embedding_inference_backend,
                    "face_embedding_inference_backend",
                ),
            ] {
                nonempty(value.as_deref().unwrap_or_default(), field)?;
            }
        }
        self.validate_di()?;
        for id in self.extra_normalized.keys() {
            let referenced = source
                .info
                .left_ir_multiframe_image_ids
                .iter()
                .chain(&source.info.right_ir_multiframe_image_ids)
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

    /// Both eyes are present, every vector has one length, floats are finite,
    /// quantized values fit `i8` and share values `u16`, the producer's types,
    /// and the embeddings and all three shares agree on their model, embedding
    /// and sharing versions.
    fn validate_di(&self) -> Result<(), Error> {
        const INVALID_EMBEDDINGS: Error = Error::InvalidField("di_embeddings");
        const INVALID_SHARES: Error = Error::InvalidField("di_embedding_shares");
        let embedding = self
            .di_embeddings
            .embedding_v1
            .as_ref()
            .ok_or(INVALID_EMBEDDINGS)?;
        nonempty(&embedding.model_version, "di_model_version")?;
        nonempty(
            &embedding.embedding_inference_backend,
            "di_inference_backend",
        )?;
        nonempty(&embedding.embedding_version, "di_embedding_version")?;
        let n = embedding.left_embedding.len();
        let quantized = [
            &embedding.left_embedding,
            &embedding.left_mirror_embedding,
            &embedding.right_embedding,
            &embedding.right_mirror_embedding,
        ];
        let floats = [
            &embedding.left_embedding_f32,
            &embedding.left_mirror_embedding_f32,
            &embedding.right_embedding_f32,
            &embedding.right_mirror_embedding_f32,
        ];
        if n == 0
            || n > 65536
            || quantized
                .iter()
                .any(|values| values.len() != n || values.iter().any(|v| i8::try_from(*v).is_err()))
            || floats
                .iter()
                .any(|values| values.len() != n || values.iter().any(|v| !v.is_finite()))
        {
            return Err(INVALID_EMBEDDINGS);
        }
        let mut shares_version = None;
        for share in &self.di_embedding_shares {
            let share = share.share_v1.as_ref().ok_or(INVALID_SHARES)?;
            nonempty(&share.shares_version, "di_shares_version")?;
            if share.model_version != embedding.model_version
                || share.embedding_version != embedding.embedding_version
                || *shares_version.get_or_insert(&share.shares_version) != &share.shares_version
                || [
                    &share.left_share,
                    &share.left_mirror_share,
                    &share.right_share,
                    &share.right_mirror_share,
                ]
                .iter()
                .any(|values| {
                    values.len() != n || values.iter().any(|v| u16::try_from(*v).is_err())
                })
            {
                return Err(INVALID_SHARES);
            }
        }
        Ok(())
    }
}

pub(crate) fn nonempty(value: &str, field: &'static str) -> Result<(), Error> {
    if value.is_empty() || value.len() > 1024 * 1024 {
        Err(Error::InvalidField(field))
    } else {
        Ok(())
    }
}
