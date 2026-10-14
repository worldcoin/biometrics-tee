//! One fresh set of image recipients per output PCP.
//!
//! Public keys stay paired
//! with their KMS envelopes; plaintext private keys use libsodium guarded memory.

use alkali::asymmetric::seal::curve25519xsalsa20poly1305 as sealedbox;
use di_migration_pcp::{MigrationContext, OutputRecipients, PreparedBiometrics, SourcePcp};

use crate::kms;

/// Failure to generate or wrap one of the four recipient keys.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The cryptographic library could not allocate or generate a keypair.
    #[error("PCP recipient key generation failed")]
    Generation,
    /// Wrapping failed for a fixed archive role; no usable bundle is returned.
    #[error("PCP {role} key wrapping failed: {source}")]
    Wrapping {
        /// Archive role, never a user-supplied identifier.
        role: &'static str,
        /// Payload-free KMS failure.
        #[source]
        source: kms::Error,
    },
}

struct WrappedKey {
    public_key: [u8; 32],
    encrypted_private_key: String,
}

impl WrappedKey {
    async fn generate(wrapper: &kms::KeyWrapper, role: &'static str) -> Result<Self, Error> {
        let pair = sealedbox::Keypair::generate().map_err(|_| Error::Generation)?;
        let private_key = pair.private_key.as_ref();
        let encrypted_private_key = wrapper.wrap(private_key).await.map_err(|source| {
            tracing::warn!(role, reason = %source, "PCP key wrapping failed");
            Error::Wrapping { role, source }
        })?;
        // Dropping `pair` clears its guarded private-key buffer. SDK request copies
        // are transient and must never be captured by HTTP body logging.
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

/// A complete set of public recipients and encrypted private keys, owned by one
/// migration. Construction is all-or-nothing; plaintext private keys are not retained.
pub struct WrappedPcpKeys {
    iris: WrappedKey,
    normalized_iris: WrappedKey,
    face: WrappedKey,
    tier2: WrappedKey,
}

impl WrappedPcpKeys {
    /// Generates four independent keypairs and wraps each private key. Operations
    /// run sequentially, bounding KMS concurrency to one call per migration.
    ///
    /// # Errors
    /// Returns the first generation or wrapping failure, discarding partial results.
    pub async fn generate(wrapper: &kms::KeyWrapper) -> Result<Self, Error> {
        Ok(Self {
            iris: WrappedKey::generate(wrapper, "iris").await?,
            normalized_iris: WrappedKey::generate(wrapper, "normalized_iris").await?,
            face: WrappedKey::generate(wrapper, "face").await?,
            tier2: WrappedKey::generate(wrapper, "tier2").await?,
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

/// Errors from the recipient, mapping or shared-builder stages.
#[derive(Debug, thiserror::Error)]
pub enum BuildError<E> {
    /// Prepared source or biometrics failed validation.
    #[error(transparent)]
    Mapping(#[from] di_migration_pcp::Error),
    /// Archive assembly, encryption or the supplied signer failed.
    #[error("PCP construction failed")]
    Build(#[source] orb_pcp::BuildError<E>),
}

/// Builds one encrypted PCP with KMS-wrapped recipients.
///
/// The caller owns
/// source authentication, inference, user-key authorization and the signer.
/// Generate the keys asynchronously first, then call this synchronous function
/// on a blocking worker together with the other CPU-bound migration stages.
///
/// # Errors
/// Propagates mapping and builder failures; no partial package is returned.
pub fn build<E>(
    keys: &WrappedPcpKeys,
    source: &SourcePcp,
    biometrics: &PreparedBiometrics<'_>,
    context: &MigrationContext,
    user_public_key: &[u8; 32],
    sign_digest: impl FnOnce(&[u8; 32]) -> Result<Vec<u8>, E>,
) -> Result<orb_pcp::Package, BuildError<E>> {
    di_migration_pcp::with_build_request(
        source,
        biometrics,
        context,
        keys.recipients(user_public_key),
        |request| orb_pcp::build(request, &mut rand::rngs::OsRng, sign_digest),
    )?
    .map_err(BuildError::Build)
}
