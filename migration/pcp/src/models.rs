use serde::{Deserialize, Serialize};

/// v2.8 capture metadata plus the v2.9 source signup, with explicit absence.
/// Lists use `Option` as well: unavailable is distinct from a known empty list.
/// Salts are retained only for unchanged source values. The builder must generate
/// fresh salts for new identity fields and rebuild all hashes over final bytes.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Info {
    pub signup_id: Option<String>,
    pub src_signup_id: Option<String>,
    pub signup_id_salt: Option<String>,
    pub signup_reason: Option<String>,
    pub signup_reason_salt: Option<String>,
    pub orb_id: Option<String>,
    pub orb_id_salt: Option<String>,
    pub operator_id: Option<String>,
    pub operator_id_salt: Option<String>,
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    pub timestamp: Option<String>,
    pub timestamp_salt: Option<String>,
    pub software_version: Option<String>,
    pub software_version_salt: Option<String>,
    pub qr_code: Option<String>,
    pub qr_code_salt: Option<String>,
    pub orb_country: Option<String>,
    pub orb_country_salt: Option<String>,
    pub id_commitment: Option<String>,
    pub id_commitment_salt: Option<String>,
    pub device_public_key: Option<String>,
    pub device_public_key_salt: Option<String>,
    pub orb_public_key_certificate: Option<String>,
    pub left_ir_image_id: Option<String>,
    pub right_ir_image_id: Option<String>,
    pub thumbnail_image_id: Option<String>,
    pub left_ir_multiframe_image_ids: Option<Vec<String>>,
    pub right_ir_multiframe_image_ids: Option<Vec<String>>,
    pub left_iris_code_aggregate_image_ids: Option<Vec<String>>,
    pub right_iris_code_aggregate_image_ids: Option<Vec<String>>,
}

fn deserialize_timestamp<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Timestamp {
        Integer(u64),
        Text(String),
    }
    let value = Option::<Timestamp>::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(Timestamp::Integer(n)) => Ok(Some(n.to_string())),
        Some(Timestamp::Text(s))
            if !s.is_empty()
                && s.bytes().all(|b| b.is_ascii_digit())
                && s.parse::<u64>().is_ok() =>
        {
            Ok(Some(s))
        }
        Some(Timestamp::Text(_)) => Err(serde::de::Error::custom("expected Unix seconds")),
    }
}

/// A source encryption-key envelope. Its presence is not authorization to reuse
/// the recipient or to encrypt new artifacts with the historical key.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendKey {
    pub public_key: Option<String>,
    pub encrypted_private_key: Option<String>,
}

/// v2.8 backend roles. Older versions may lack any of these envelopes.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendKeys {
    pub iris: Option<BackendKey>,
    pub normalized_iris: Option<BackendKey>,
    pub face: Option<BackendKey>,
    pub tier2: Option<BackendKey>,
}

/// Allowlisted pipeline provenance; debug reports travel on the separate debug
/// channel and are never automatically embedded in a PCP or in logs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineMetadata {
    pub biometric_pipeline_version: String,
    pub di_model_version: String,
    pub iris_version: String,
    pub di_inference_backend: String,
    pub duration_ms: Option<u64>,
}
