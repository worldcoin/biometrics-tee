use ampc_secret_sharing::{
    GaloisRingElement, PartyID, ShamirGaloisRingShare, basis,
    iris_vector::{IRIS_VECTOR_SIZE, IrisVector},
};
use di_migration_shares::{Error, generate};
use rand::{RngCore, SeedableRng, rngs::StdRng};

fn embedding(offset: usize) -> [u8; IRIS_VECTOR_SIZE] {
    std::array::from_fn(|i| (i8::try_from((i + offset) % 16).unwrap() - 8).cast_unsigned())
}

#[test]
fn matches_upstream_shares_and_recipient_order() {
    let mut actual_rng = StdRng::seed_from_u64(42);
    let mut expected_rng = actual_rng.clone();
    // Distinct synthetic originals and mirrors for two eyes, using one RNG stream.
    for offset in [0, 1, 4, 5] {
        let input = embedding(offset);
        let actual = generate(&input, &mut actual_rng).unwrap();
        let expected = IrisVector::new(input.map(u8::cast_signed))
            .secret_share(&mut expected_rng)
            .unwrap()
            .map(|share| share.to_vec());
        assert_eq!(actual.shares, expected);
    }
}

#[test]
fn every_pair_of_recipients_reconstructs_each_embedding() {
    let mut rng = StdRng::seed_from_u64(7);
    let parties = [PartyID::ID0, PartyID::ID1, PartyID::ID2];
    for offset in [0, 1, 4, 5] {
        let expected = embedding(offset);
        let vectors = generate(&expected, &mut rng).unwrap().shares;
        assert!(vectors.iter().all(|share| share.len() == IRIS_VECTOR_SIZE));
        for (a, b) in [(0, 1), (0, 2), (1, 2)] {
            let weights = [
                ShamirGaloisRingShare::deg_1_lagrange_polys_at_zero(parties[a], parties[b]),
                ShamirGaloisRingShare::deg_1_lagrange_polys_at_zero(parties[b], parties[a]),
            ];
            for i in (0..IRIS_VECTOR_SIZE).step_by(4) {
                let left = GaloisRingElement::<basis::Monomial>::from_coefs(
                    vectors[a][i..i + 4].try_into().unwrap(),
                );
                let right = GaloisRingElement::<basis::Monomial>::from_coefs(
                    vectors[b][i..i + 4].try_into().unwrap(),
                );
                let recovered = (left * weights[0] + right * weights[1]).to_basis_A();
                // Compare the full ring coefficients, including sign extension.
                let expected: [u16; 4] = std::array::from_fn(|j| {
                    u16::from_ne_bytes(i16::from(expected[i + j].cast_signed()).to_ne_bytes())
                });
                assert_eq!(recovered.coefs, expected);
            }
        }
    }
}

#[test]
fn repeated_embeddings_receive_fresh_shares() {
    let input = embedding(0);
    let mut rng = StdRng::seed_from_u64(123);
    let first = generate(&input, &mut rng).unwrap();
    let second = generate(&input, &mut rng).unwrap();
    for recipient in 0..3 {
        assert_ne!(first.shares[recipient], second.shares[recipient]);
    }
}

#[test]
fn invalid_inputs_are_rejected_before_consuming_randomness() {
    let valid = embedding(0);
    let mut malformed = vec![
        vec![],
        vec![0; IRIS_VECTOR_SIZE - 1],
        vec![0; IRIS_VECTOR_SIZE + 1],
    ];
    for value in [8u8, (-9i8).cast_unsigned(), 127, 128] {
        let mut input = valid.to_vec();
        input[IRIS_VECTOR_SIZE - 1] = value;
        malformed.push(input);
    }
    for invalid in malformed {
        let mut rng = StdRng::seed_from_u64(99);
        let mut untouched = rng.clone();
        let error = generate(&invalid, &mut rng).err().unwrap();
        match error {
            Error::InvalidLength { actual } => {
                assert_eq!(actual, invalid.len());
                assert_ne!(actual, IRIS_VECTOR_SIZE);
            }
            Error::InvalidValue => {
                assert_eq!(invalid.len(), IRIS_VECTOR_SIZE);
            }
            Error::Sharing { .. } => panic!("validation must precede sharing"),
        }
        assert_eq!(rng.next_u64(), untouched.next_u64());
    }
}
