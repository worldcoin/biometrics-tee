use ampc_secret_sharing::{FaceVector, GaloisRingElement, PartyID, ShamirGaloisRingShare, basis};
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use selfie_enrollment_sealed_types::FaceEmbedding;
use selfie_enrollment_shares::{FaceShare, generate};

// Frozen IEEE-754 inputs and expected quantization, including ties, saturation,
// signed zero, finite extrema, and a value immediately above the negative 7.5 tie.
const CASES: [(u32, i8); 17] = [
    (0xbc2a_6be9, 0),
    (0x3c2a_6be9, 0),
    (0xbcff_a1de, -2),
    (0x3cff_a1de, 2),
    (0xbd55_06e3, -2),
    (0x3d55_06e3, 2),
    (0xbe0a_77ad, -6),
    (0x3e0a_77ad, 6),
    (0xbe2a_6be9, -8),
    (0x3e2a_6be9, 7),
    (0xbed5_06e3, -8),
    (0x3ed5_06e3, 7),
    (0x0000_0000, 0),
    (0x8000_0000, 0),
    (0x7f7f_ffff, 7),
    (0xff7f_ffff, -8),
    (0xbe1f_c52a, -7),
];

fn wire_input() -> Vec<u8> {
    // Bincode 1 fixed-int Vec length, then 512 little-endian float bit patterns.
    // Do not use the production decoder's serializer to construct its fixture.
    let mut bytes = vec![0x00, 0x02, 0, 0, 0, 0, 0, 0];
    for i in 0..512 {
        bytes.extend_from_slice(&CASES[i % CASES.len()].0.to_le_bytes());
    }
    bytes
}

fn embedding(bytes: &[u8]) -> FaceEmbedding {
    FaceEmbedding {
        embedding: STANDARD.encode(bytes),
        embedding_type: "ghostfacenet_flipped_mean".into(),
        embedding_version: "2.0.0".into(),
        embedding_inference_backend: "face-engine".into(),
    }
}

fn decode_share(share: &FaceShare) -> Vec<u16> {
    let json = serde_json::to_vec(share).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(
        parsed,
        serde_json::json!({"version": "1", "share_data": share.share_data})
    );
    let bytes = STANDARD
        .decode(parsed["share_data"].as_str().unwrap())
        .unwrap();
    assert_eq!(bytes.len(), 1024);
    assert_eq!(STANDARD.encode(&bytes), share.share_data);
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes(*b))
        .collect()
}

#[test]
fn frozen_wire_input_matches_quantization_and_upstream_recipient_order() {
    let expected = std::array::from_fn(|i| CASES[i % CASES.len()].1);
    for kind in ["ghostfacenet", "ghostfacenet_flipped_mean"] {
        let mut input = embedding(&wire_input());
        input.embedding_type = kind.into();
        let mut rng = StdRng::seed_from_u64(42);
        let mut reference_rng = rng.clone();
        let actual = generate(&input, "1", &mut rng).unwrap();
        let upstream = FaceVector::new(expected)
            .secret_share(&mut reference_rng)
            .unwrap();
        for i in 0..3 {
            assert_eq!(decode_share(&actual[i]), upstream[i].0);
        }
    }
}

#[test]
fn every_recipient_pair_reconstructs_the_quantized_embedding() {
    let output = generate(
        &embedding(&wire_input()),
        "1",
        &mut StdRng::seed_from_u64(7),
    )
    .unwrap();
    let vectors = output.each_ref().map(decode_share);
    let parties = [PartyID::ID0, PartyID::ID1, PartyID::ID2];
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        let wa = ShamirGaloisRingShare::deg_1_lagrange_polys_at_zero(parties[a], parties[b]);
        let wb = ShamirGaloisRingShare::deg_1_lagrange_polys_at_zero(parties[b], parties[a]);
        for i in (0..512).step_by(4) {
            let left = GaloisRingElement::<basis::Monomial>::from_coefs(
                vectors[a][i..i + 4].try_into().unwrap(),
            );
            let right = GaloisRingElement::<basis::Monomial>::from_coefs(
                vectors[b][i..i + 4].try_into().unwrap(),
            );
            let expected: [u16; 4] = std::array::from_fn(|j| {
                u16::from_ne_bytes(i16::from(CASES[(i + j) % CASES.len()].1).to_ne_bytes())
            });
            assert_eq!((left * wa + right * wb).to_basis_A().coefs, expected);
        }
    }
}

#[test]
fn trailing_bytes_remain_compatible_and_repeated_calls_use_fresh_randomness() {
    let mut bytes = wire_input();
    let mut rng = StdRng::seed_from_u64(123);
    let first = generate(&embedding(&bytes), "1", &mut rng).unwrap();
    let second = generate(&embedding(&bytes), "1", &mut rng).unwrap();
    bytes.extend_from_slice(b"upstream permits trailing bytes");
    let trailing = generate(&embedding(&bytes), "1", &mut StdRng::seed_from_u64(123)).unwrap();
    for i in 0..3 {
        assert_eq!(first[i].share_data, trailing[i].share_data);
        assert_ne!(first[i].share_data, second[i].share_data);
    }
}

#[test]
fn invalid_input_is_rejected_without_consuming_randomness() {
    let wire = wire_input();
    let mut invalid = vec![embedding(&[]), embedding(&wire[..wire.len() - 1])];
    for length in [0_u64, 511, 513, u64::MAX] {
        let mut bytes = wire.clone();
        bytes[..8].copy_from_slice(&length.to_le_bytes());
        invalid.push(embedding(&bytes));
    }
    for bits in [0x7fc0_0000_u32, 0x7f80_0000, 0xff80_0000] {
        let mut bytes = wire.clone();
        bytes[2048..2052].copy_from_slice(&bits.to_le_bytes());
        invalid.push(embedding(&bytes));
    }
    for field in ["base64", "size", "type", "version", "backend"] {
        let mut input = embedding(&wire);
        match field {
            "base64" => input.embedding = "not base64!".into(),
            "size" => input.embedding = "A".repeat(4100),
            "type" => input.embedding_type = "unknown".into(),
            "version" => input.embedding_version = "1.0.0".into(),
            "backend" => input.embedding_inference_backend = "unknown".into(),
            _ => unreachable!(),
        }
        invalid.push(input);
    }
    for input in invalid {
        let mut rng = StdRng::seed_from_u64(99);
        let mut untouched = rng.clone();
        assert!(generate(&input, "1", &mut rng).is_err());
        assert_eq!(rng.next_u64(), untouched.next_u64());
    }
}
