//! Convert legacy-normalized fields to the shared generated PCP messages.
//! Keep original bytes separately: protojson output is not a signing preimage.

use crate::Info;

impl From<Info> for orb_pcp_defs::v1::Info {
    /// The shared v1 schema uses repeated fields, so an unavailable source list
    /// becomes an empty vector here.
    fn from(info: Info) -> Self {
        Self {
            signup_id: info.signup_id,
            signup_id_salt: info.signup_id_salt,
            signup_reason: info.signup_reason,
            signup_reason_salt: info.signup_reason_salt,
            orb_id: info.orb_id,
            orb_id_salt: info.orb_id_salt,
            operator_id: info.operator_id,
            operator_id_salt: info.operator_id_salt,
            timestamp: info.timestamp,
            timestamp_salt: info.timestamp_salt,
            qr_code: info.qr_code,
            qr_code_salt: info.qr_code_salt,
            orb_public_key_certificate: info.orb_public_key_certificate,
            left_ir_image_id: info.left_ir_image_id,
            left_ir_multiframe_image_ids: info.left_ir_multiframe_image_ids.unwrap_or_default(),
            left_iris_code_aggregate_image_ids: info
                .left_iris_code_aggregate_image_ids
                .unwrap_or_default(),
            right_ir_image_id: info.right_ir_image_id,
            right_ir_multiframe_image_ids: info.right_ir_multiframe_image_ids.unwrap_or_default(),
            right_iris_code_aggregate_image_ids: info
                .right_iris_code_aggregate_image_ids
                .unwrap_or_default(),
            thumbnail_image_id: info.thumbnail_image_id,
            software_version: info.software_version,
            software_version_salt: info.software_version_salt,
            orb_country: info.orb_country,
            orb_country_salt: info.orb_country_salt,
            id_commitment: info.id_commitment,
            id_commitment_salt: info.id_commitment_salt,
            device_public_key: info.device_public_key,
            device_public_key_salt: info.device_public_key_salt,
        }
    }
}
