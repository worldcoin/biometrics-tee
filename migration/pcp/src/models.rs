use serde::{Deserialize, Serialize};

/// v2.8 capture metadata, with explicit absence.
/// Lists use `Option` as well: unavailable is distinct from a known empty list.
/// Source salts are parsed but never emitted: the builder generates a fresh salt
/// and hash for every salted value it writes.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Info {
    pub signup_id: Option<String>,
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
        // Canonical decimal only: the builder re-renders capture time from its
        // integer value, so leading zeros or a sign could not be preserved.
        Some(Timestamp::Text(s)) if s.parse::<u64>().is_ok_and(|n| n.to_string() == s) => {
            Ok(Some(s))
        }
        Some(Timestamp::Text(_)) => Err(serde::de::Error::custom("expected Unix seconds")),
    }
}
