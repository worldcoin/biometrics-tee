//! Nonce ownership for the draft challenge contract. Not exposed by the RPC router.
//!
//! Run creation/authorization, expiry, randomness verification, signing and reveal
//! gating are subsequent work. This helper must only receive enclave-owned context.
use rand::{CryptoRng, RngCore, rngs::OsRng};
use selfie_enrollment_sealed_types::challenge::{self, ChallengeContext, TargetResponses};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Contract(#[from] challenge::Error),
    #[error("challenge randomness unavailable")]
    Entropy,
}

/// Owns one nonce without serialization, cloning, Debug output or a reveal API.
/// The nonce's owned buffer is zeroized on drop.
pub struct PreparedChallenge {
    context: ChallengeContext,
    nonce: Zeroizing<[u8; 32]>,
    commitment: [u8; 32],
}

impl PreparedChallenge {
    /// The future run controller assigns a unique ID and authenticated binding.
    /// Production startup already verifies the OS RNG is backed by `nsm-hwrng`.
    pub fn generate(context: ChallengeContext) -> Result<Self, Error> {
        Self::with_rng(context, &mut OsRng)
    }

    fn with_rng(
        context: ChallengeContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, Error> {
        context.validate()?;
        let mut nonce = Zeroizing::new([0; 32]);
        rng.try_fill_bytes(nonce.as_mut())
            .map_err(|_| Error::Entropy)?;
        let commitment = challenge::commitment(&context, &nonce)?;
        Ok(Self {
            context,
            nonce,
            commitment,
        })
    }

    pub fn context(&self) -> &ChallengeContext {
        &self.context
    }

    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    /// Pure derivation, not instruction issuance. The future controller must admit
    /// exactly one verified value for the committed source/round before calling it.
    pub fn target_responses(
        &self,
        external_randomness: &[u8; 32],
    ) -> Result<TargetResponses, Error> {
        Ok(challenge::derive_target_responses(
            &self.context,
            &self.nonce,
            external_randomness,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRng {
        fail: bool,
        calls: usize,
    }
    impl CryptoRng for TestRng {}
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            panic!("use fallible byte generation")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("use fallible byte generation")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("use fallible byte generation")
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.calls += 1;
            // Deliberately write before returning an error to exercise the failure path.
            dest.fill(7);
            if self.fail {
                Err(rand::Error::from(
                    std::num::NonZeroU32::new(rand::Error::CUSTOM_START).unwrap(),
                ))
            } else {
                Ok(())
            }
        }
    }

    fn context() -> ChallengeContext {
        ChallengeContext {
            contract_version: challenge::CONTRACT_VERSION,
            generator_version: challenge::GENERATOR_VERSION,
            evaluator_version: challenge::EVALUATOR_VERSION,
            challenge_id: [1; 16],
            session_binding: [2; 32],
            expires_at_unix_ms: 1792692000000,
            policy_digest: [3; 32],
            randomness_source: [4; 32],
            randomness_round: 123456,
        }
    }

    #[test]
    fn preparation_keeps_the_original_context_and_nonce_for_generation() {
        let context = context();
        let mut rng = TestRng {
            fail: false,
            calls: 0,
        };
        let prepared = PreparedChallenge::with_rng(context.clone(), &mut rng).unwrap();
        assert_eq!(rng.calls, 1);
        assert_eq!(prepared.context(), &context);
        assert_eq!(
            prepared.commitment(),
            challenge::commitment(&context, &[7; 32]).unwrap()
        );
        let expected = challenge::derive_target_responses(&context, &[7; 32], &[8; 32]).unwrap();
        assert_eq!(prepared.target_responses(&[8; 32]).unwrap(), expected);
        assert_eq!(prepared.target_responses(&[8; 32]).unwrap(), expected);
        assert_eq!(rng.calls, 1);
    }

    #[test]
    fn entropy_failure_does_not_create_a_challenge() {
        let mut rng = TestRng {
            fail: true,
            calls: 0,
        };
        assert!(matches!(
            PreparedChallenge::with_rng(context(), &mut rng),
            Err(Error::Entropy)
        ));
        assert_eq!(rng.calls, 1);
    }

    #[test]
    fn invalid_context_is_rejected_before_requesting_randomness() {
        let mut rng = TestRng {
            fail: false,
            calls: 0,
        };
        let mut context = context();
        context.generator_version = 2;
        assert!(matches!(
            PreparedChallenge::with_rng(context, &mut rng),
            Err(Error::Contract(challenge::Error::UnsupportedVersion))
        ));
        assert_eq!(rng.calls, 0);
    }
}
