use ampc_secret_sharing::{
    GaloisRingElement, basis,
    iris_vector::{IRIS_VECTOR_SIZE, IrisVector},
};
use di_migration_shares::{Error, generate_5_party};
use rand::{RngCore, SeedableRng, rngs::StdRng};

fn embedding(offset: usize) -> [u8; IRIS_VECTOR_SIZE] {
    std::array::from_fn(|i| (i8::try_from((i + offset) % 16).unwrap() - 8).cast_unsigned())
}

#[test]
fn matches_upstream_shares_and_recipient_order() {
    let mut actual_rng = StdRng::seed_from_u64(42);
    let mut expected_rng = actual_rng.clone();
    for offset in [0, 1, 4, 5] {
        let input = embedding(offset);
        let actual = generate_5_party(&input, &mut actual_rng).unwrap();
        let expected = IrisVector::new(input.map(u8::cast_signed))
            .secret_share_5_parties(&mut expected_rng)
            .unwrap()
            .map(|share| share.to_vec());
        assert_eq!(actual, expected);
        assert!(actual.iter().all(|share| share.len() == IRIS_VECTOR_SIZE));
    }
}

#[test]
fn every_triple_of_recipients_reconstructs_each_embedding() {
    type Ring = GaloisRingElement<basis::Monomial>;

    let mut rng = StdRng::seed_from_u64(7);
    for offset in [0, 1, 4, 5] {
        let expected = embedding(offset);
        let vectors = generate_5_party(&expected, &mut rng).unwrap();
        for a in 0..3 {
            for b in a + 1..4 {
                for c in b + 1..5 {
                    let recipients = [a, b, c];
                    // PartyID is three-party-only. Numeric evaluation points let
                    // us compute degree-two weights for every recipient triple.
                    let weights = recipients.map(|recipient| {
                        let x = Ring::EXCEPTIONAL_SEQUENCE[recipient + 1];
                        recipients.iter().filter(|&&other| other != recipient).fold(
                            Ring::ONE,
                            |weight, &other| {
                                let y = Ring::EXCEPTIONAL_SEQUENCE[other + 1];
                                weight * (-y) * (x - y).inverse()
                            },
                        )
                    });
                    for i in (0..IRIS_VECTOR_SIZE).step_by(4) {
                        let recovered = recipients
                            .into_iter()
                            .zip(weights)
                            .fold(Ring::ZERO, |sum, (recipient, weight)| {
                                let share = Ring::from_coefs(
                                    vectors[recipient][i..i + 4].try_into().unwrap(),
                                );
                                sum + share * weight
                            })
                            .to_basis_A();
                        let expected: [u16; 4] = std::array::from_fn(|j| {
                            u16::from_ne_bytes(
                                i16::from(expected[i + j].cast_signed()).to_ne_bytes(),
                            )
                        });
                        assert_eq!(recovered.coefs, expected, "recipients {recipients:?}");
                    }
                }
            }
        }
    }
}

#[test]
fn repeated_embeddings_receive_fresh_shares() {
    let input = embedding(0);
    let mut rng = StdRng::seed_from_u64(123);
    let first = generate_5_party(&input, &mut rng).unwrap();
    let second = generate_5_party(&input, &mut rng).unwrap();
    for recipient in 0..5 {
        assert_ne!(first[recipient], second[recipient]);
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
        let error = generate_5_party(&invalid, &mut rng).unwrap_err();
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
