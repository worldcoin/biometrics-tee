use ampc_secret_sharing::{GaloisRingElement, PartyID, ShamirGaloisRingShare, basis};
use base64::{Engine, engine::general_purpose::STANDARD};
use crypto_box::{PublicKey, SecretKey};
use embedding_shares::{Error, FaceShare, encrypt, generate};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use selfie_enrollment_sealed_types::FaceEmbedding;

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
fn frozen_wire_input_matches_pinned_oxide_serialized_shares() {
    for kind in ["ghostfacenet", "ghostfacenet_flipped_mean"] {
        let mut input = embedding(&wire_input());
        input.embedding_type = kind.into();
        let mut rng = StdRng::seed_from_u64(42);
        let actual = generate(&input, "1", &mut rng).unwrap();
        assert_eq!(
            serde_json::to_string(&actual).unwrap(),
            include_str!("fixtures/oxide-shares.json").trim(),
            "embedding type: {kind}"
        );
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

#[test]
fn encrypted_shares_decrypt_to_oxide_json_in_recipient_order() {
    let mut rng = StdRng::seed_from_u64(42);
    let shares = generate(&embedding(&wire_input()), "4.0", &mut rng).unwrap();
    let secret_keys = [1_u8, 2, 3].map(|value| SecretKey::from([value; 32]));
    let public_keys = secret_keys.each_ref().map(SecretKey::public_key);
    let ciphertexts = encrypt(&shares, &public_keys, &mut rng).unwrap();

    for party in 0..3 {
        let ciphertext = STANDARD.decode(&ciphertexts[party]).unwrap();
        assert_eq!(STANDARD.encode(&ciphertext), ciphertexts[party]);
        let plaintext = secret_keys[party].unseal(&ciphertext).unwrap();
        let expected = format!(
            r#"{{"version":"4.0","share_data":"{}"}}"#,
            shares[party].share_data
        );
        assert_eq!(plaintext, expected.as_bytes());
        assert_eq!(shares[party].version, "4.0");
        assert_eq!(ciphertext.len(), plaintext.len() + crypto_box::SEALBYTES);
        for (other_party, other_key) in secret_keys.iter().enumerate() {
            if other_party != party {
                assert!(other_key.unseal(&ciphertext).is_err());
            }
        }
        let mut tampered = ciphertext;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(secret_keys[party].unseal(&tampered).is_err());
    }
}

#[test]
fn repeated_encryption_uses_fresh_randomness() {
    let mut rng = StdRng::seed_from_u64(7);
    let shares = generate(&embedding(&wire_input()), "1", &mut rng).unwrap();
    let public_keys = [1_u8, 2, 3].map(|value| SecretKey::from([value; 32]).public_key());
    let first = encrypt(&shares, &public_keys, &mut rng).unwrap();
    let second = encrypt(&shares, &public_keys, &mut rng).unwrap();
    for party in 0..3 {
        assert_ne!(first[party], second[party]);
    }
}

#[test]
fn invalid_recipients_are_rejected_before_consuming_randomness() {
    let shares = generate(
        &embedding(&wire_input()),
        "1",
        &mut StdRng::seed_from_u64(42),
    )
    .unwrap();
    let public_keys = [1_u8, 2, 3].map(|value| SecretKey::from([value; 32]).public_key());
    let mut one = [0; 32];
    one[0] = 1;
    for low_order_key in [[0; 32], one] {
        for party in 0..3 {
            let mut invalid = public_keys.clone();
            invalid[party] = PublicKey::from(low_order_key);
            assert_invalid_recipients(&shares, &invalid, party);
        }
    }
    for (first, second) in [(0, 1), (0, 2), (1, 2)] {
        let mut invalid = public_keys.clone();
        invalid[second] = invalid[first].clone();
        assert_invalid_recipients(&shares, &invalid, second);

        // X25519 ignores the top bit; an alternate encoding is still a duplicate.
        let mut alias = invalid[second].to_bytes();
        alias[31] ^= 0x80;
        invalid[second] = PublicKey::from(alias);
        assert_invalid_recipients(&shares, &invalid, second);
    }
}

fn assert_invalid_recipients(shares: &[FaceShare; 3], public_keys: &[PublicKey; 3], party: usize) {
    let mut rng = StdRng::seed_from_u64(123);
    let mut untouched = rng.clone();
    assert_eq!(
        encrypt(shares, public_keys, &mut rng),
        Err(Error::InvalidRecipient { party })
    );
    assert_eq!(rng.next_u64(), untouched.next_u64());
}
