//! One fresh set of image recipients per output PCP.
//!
//! Public keys stay paired
//! with their KMS envelopes; plaintext private keys use libsodium guarded memory.

use alkali::asymmetric::seal::curve25519xsalsa20poly1305 as sealedbox;
use di_migration_pcp::OutputRecipients;

use crate::kms;

/// Failure to generate or wrap one of the four recipient keys.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The cryptographic library could not allocate or generate a keypair.
    #[error("PCP recipient key generation failed")]
    Generation,
    /// Wrapping failed for a fixed archive role; no usable bundle is returned.
    #[error("PCP {archive_role} key wrapping failed: {source}")]
    Wrapping {
        /// Archive role, never a user-supplied identifier.
        archive_role: &'static str,
        /// Payload-free KMS failure.
        #[source]
        source: kms::Error,
    },
}

struct PublicPrivateKeypair {
    public_key: [u8; 32],
    encrypted_private_key: String,
}

impl PublicPrivateKeypair {
    async fn generate(
        wrapper: &kms::KeyWrapper,
        archive_role: &'static str,
    ) -> Result<Self, Error> {
        let pair = sealedbox::Keypair::generate().map_err(|_| Error::Generation)?;
        let private_key = pair.private_key.as_ref();
        let encrypted_private_key = wrapper.encrypt(private_key).await.map_err(|source| {
            tracing::warn!(archive_role, reason = %source, "PCP key wrapping failed");
            Error::Wrapping {
                archive_role,
                source,
            }
        })?;
        // Dropping `pair` clears its guarded private-key buffer. KMS serialization
        // uses a separate zeroizing body shared by request attempts.
        Ok(Self {
            public_key: pair.public_key,
            encrypted_private_key,
        })
    }

    fn recipient(&self) -> orb_pcp::BackendKey<'_> {
        orb_pcp::BackendKey {
            public_key: &self.public_key,
            encrypted_private_key: &self.encrypted_private_key,
        }
    }
}

/// Four public recipients and their KMS-encrypted private keys for one migration.
///
/// Returned only after all four keys have been generated and encrypted successfully.
/// Plaintext private keys are not retained.
pub struct BackendKeys {
    iris: PublicPrivateKeypair,
    normalized_iris: PublicPrivateKeypair,
    face: PublicPrivateKeypair,
    tier2: PublicPrivateKeypair,
}

impl BackendKeys {
    /// Generates four independent keypairs and wraps each private key. Operations
    /// run sequentially, bounding KMS concurrency to one call per migration.
    ///
    /// # Errors
    /// Returns the first generation or wrapping failure, discarding partial results.
    pub async fn generate(wrapper: &kms::KeyWrapper) -> Result<Self, Error> {
        Ok(Self {
            iris: PublicPrivateKeypair::generate(wrapper, "iris").await?,
            normalized_iris: PublicPrivateKeypair::generate(wrapper, "normalized_iris").await?,
            face: PublicPrivateKeypair::generate(wrapper, "face").await?,
            tier2: PublicPrivateKeypair::generate(wrapper, "tier2").await?,
        })
    }

    /// Borrows the public keys and their matching KMS envelopes for `orb-pcp`.
    #[must_use]
    pub fn recipients<'a>(&'a self, user_public_key: &'a [u8; 32]) -> OutputRecipients<'a> {
        OutputRecipients {
            user_public_key,
            backend_keys: orb_pcp::BackendKeys {
                iris: self.iris.recipient(),
                normalized_iris: self.normalized_iris.recipient(),
                face: self.face.recipient(),
                tier2: self.tier2.recipient(),
            },
        }
    }
}
