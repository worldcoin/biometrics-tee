//! Poseidon2 hashes from Oxide `32868184652c894d3bd2e7c5580dfff94f2a90a7`,
//! `oxide/src/face_enrollment/poseidon.rs`, which signup-service and the face-AMPC parties check.

use embedding_shares::FaceShare;
use selfie_enrollment_sealed_types::FaceEmbedding;
use sha3::{Digest, Sha3_256};
use world_id_primitives::{FieldElement, sponge::bytes_to_field_elements};

use crate::AssociatedData;

// DO NOT CHANGE: these tags are part of the deployed hash definitions.
const FACE_SHARE_HASH_V1: &[u8] = b"FACE_SHARE_HASH_V1";
const ID_COMMITMENT_HASH_V1: &[u8] = b"ID_COMMITMENT_HASH_V1";

pub(crate) fn share(share: &FaceShare) -> Option<FieldElement> {
    sequence(
        FACE_SHARE_HASH_V1,
        &[
            bytes(share.version.as_bytes())?,
            bytes(share.share_data.as_bytes())?,
        ],
    )
}

pub(crate) fn id_commitment(id_commitment: &str) -> Option<FieldElement> {
    sponge(ID_COMMITMENT_HASH_V1, id_commitment.as_bytes())
}

pub(crate) fn associated_data(data: &AssociatedData) -> Option<FieldElement> {
    // Oxide hashes a list as its length followed by its elements under the empty tag.
    let embeddings = sequence(
        b"",
        &[FieldElement::from(1_u64), embedding(&data.embedding)?],
    )?;
    sequence(
        FACE_SHARE_HASH_V1,
        &[
            FieldElement::from(1_u64),
            embeddings,
            FieldElement::from(data.image_png.len() as u64),
            bytes(&data.image_png)?,
            bytes(data.capture_id.as_bytes())?,
            bytes(&data.captured_at.to_be_bytes())?,
            share(&data.shares[0])?,
            share(&data.shares[1])?,
            share(&data.shares[2])?,
        ],
    )
}

fn embedding(embedding: &FaceEmbedding) -> Option<FieldElement> {
    sequence(
        FACE_SHARE_HASH_V1,
        &[
            bytes(embedding.embedding.as_bytes())?,
            bytes(embedding.embedding_type.as_bytes())?,
            bytes(embedding.embedding_version.as_bytes())?,
            bytes(embedding.embedding_inference_backend.as_bytes())?,
        ],
    )
}

/// Folds `acc = sponge(tag, acc || value)` from zero over 32-byte big-endian elements.
fn sequence(tag: &[u8], values: &[FieldElement]) -> Option<FieldElement> {
    let mut acc = FieldElement::ZERO;
    let mut buffer = [0; 64];
    for value in values {
        buffer[..32].copy_from_slice(&acc.to_be_bytes());
        buffer[32..].copy_from_slice(&value.to_be_bytes());
        acc = sponge(tag, &buffer)?;
    }
    Some(acc)
}

fn bytes(data: &[u8]) -> Option<FieldElement> {
    sponge(b"", data)
}

/// `world_id_primitives::sponge::hash_bytes_to_field_element`, which rejects the empty tag
/// since 0.14; Oxide hashes with it through 0.13. A SHA3-256 SAFE tag fills the capacity
/// element, then 31-byte chunks are absorbed 15 per Poseidon2 t16 permutation.
fn sponge(tag: &[u8], data: &[u8]) -> Option<FieldElement> {
    let length = u32::try_from(data.len())
        .ok()
        .filter(|&length| length != 0)?;
    let mut tag_input = Vec::with_capacity(8 + tag.len());
    tag_input.extend_from_slice(&0x8000_0000_u32.wrapping_add(length).to_be_bytes());
    tag_input.extend_from_slice(&32_u32.to_be_bytes());
    tag_input.extend_from_slice(tag);
    let mut state = [*FieldElement::ZERO; 16];
    state[15] += bytes_to_field_elements(32, &Sha3_256::digest(&tag_input))[0];
    for batch in data.chunks(31 * 15) {
        for (slot, element) in state.iter_mut().zip(bytes_to_field_elements(31, batch)) {
            *slot += element;
        }
        poseidon2::bn254::t16::permutation_in_place(&mut state);
    }
    Some(FieldElement::from(state[0]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use world_id_primitives::{VariableLengthDomainSeparator, sponge::hash_bytes_to_field_element};

    // Produced by Oxide's hashing code against world-id-primitives 0.13.0.
    const EMPTY_TAG_1: &str = "0x12389722106e52b4bf30d5d6fdec77e2d48b36792f289848ce3db1d6f0e8d9b0";
    const EMPTY_TAG_1000: &str =
        "0x2f471e19998d39f17b1b43ef1eef7fde0303ad4563537da1fc3a2328221783e6";
    const SHARE: &str = "0x12589d0dfa9e6a3a676d0fe9d02ff1b2a440e3101dffc874b6fecb443f17af79";
    const ID_COMMITMENT: &str =
        "0x078088c8dee297e721db84524f18ff1e1ec7d8cd33fba1a72055aed9f1c95f19";
    const ASSOCIATED_DATA: &str =
        "0x2cf18909b0d502f5a402d104587f2092c68e7c2ea334080057f980864cbb4f4d";

    fn long() -> Vec<u8> {
        (0..1000_u32).map(|i| (i * 7 + 3) as u8).collect()
    }

    fn face_share(party: u8) -> FaceShare {
        FaceShare {
            version: "1".into(),
            share_data: format!("c2hhcmU{party}"),
        }
    }

    #[test]
    fn the_sponge_matches_world_id_primitives_for_non_empty_tags() {
        const TAGS: [(&[u8], VariableLengthDomainSeparator); 2] = [
            (
                FACE_SHARE_HASH_V1,
                VariableLengthDomainSeparator::new(FACE_SHARE_HASH_V1),
            ),
            (
                ID_COMMITMENT_HASH_V1,
                VariableLengthDomainSeparator::new(ID_COMMITMENT_HASH_V1),
            ),
        ];
        let data = long();
        for (tag, separator) in TAGS {
            for length in [1, 31, 32, 465, 466, 1000] {
                assert_eq!(
                    sponge(tag, &data[..length]),
                    Some(hash_bytes_to_field_element(separator, &data[..length]).unwrap()),
                    "{length}"
                );
            }
        }
        assert_eq!(sponge(b"", b""), None);
    }

    #[test]
    fn hashes_match_oxide() {
        assert_eq!(bytes(b"a").unwrap().to_string(), EMPTY_TAG_1);
        assert_eq!(bytes(&long()).unwrap().to_string(), EMPTY_TAG_1000);
        assert_eq!(share(&face_share(0)).unwrap().to_string(), SHARE);
        assert_eq!(
            id_commitment("0x0000000000000000000000000000000000000000000000000000000000000123")
                .unwrap()
                .to_string(),
            ID_COMMITMENT
        );
        let data = AssociatedData {
            id_commitment: "excluded from the hash".into(),
            pcp_version: "1".into(),
            embedding: FaceEmbedding {
                embedding: "AQ==".into(),
                embedding_type: "ghostfacenet_flipped_mean".into(),
                embedding_version: "2.0.0".into(),
                embedding_inference_backend: "face-engine".into(),
            },
            image_png: [b"\x89PNG\r\n\x1a\n".as_slice(), &long()].concat(),
            capture_id: "6f9619ff-8b86-4d01-b42d-00cf4fc964ff".into(),
            captured_at: 1_700_000_000,
            shares: [face_share(0), face_share(1), face_share(2)],
        };
        assert_eq!(associated_data(&data).unwrap().to_string(), ASSOCIATED_DATA);
    }
}
