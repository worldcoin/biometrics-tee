//! Turn an opened source and this run's outputs into the shared builder's
//! migration request.

use std::collections::{BTreeMap, BTreeSet};

use alkali::{
    AlkaliError,
    asymmetric::seal::{SealError, curve25519xsalsa20poly1305 as sealedbox},
};
use orb_pcp::ImageId;
use orb_pcp_defs::v1;

use crate::mapping::nonempty;
use crate::source::raw_image;
use crate::{Error, Files, MigrationContext, PreparedBiometrics, SourcePcp};

/// Recipient keys for the new package: the user key encrypts the tiers, the
/// backend keys encrypt the inner archives and are written to `backend_keys.json`.
pub struct OutputRecipients<'a> {
    pub user_public_key: &'a [u8; 32],
    pub backend_keys: orb_pcp::BackendKeys<'a>,
}

/// Failure to prepare or construct a migrated package.
#[derive(Debug, thiserror::Error)]
pub enum BuildError<E> {
    /// Prepared source, biometrics or migration context failed validation.
    #[error(transparent)]
    Mapping(#[from] Error),
    /// Archive assembly, encryption or the supplied signer failed.
    #[error(transparent)]
    Build(orb_pcp::BuildError<E, SealingError>),
}

/// Failure to seal a PCP tier or inner archive.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SealingError {
    #[error("recipient public key has unacceptable low order")]
    InvalidRecipient,
    #[error("sealed-box encryption failed")]
    Library(#[source] AlkaliError),
}

/// Libsodium-compatible sealed boxes with fresh ephemeral keys per call.
/// Preserve the exact recipient bytes: they are part of the nonce derivation.
fn seal(plaintext: &[u8], recipient: &[u8; 32]) -> Result<Vec<u8>, SealingError> {
    let mut ciphertext = vec![0; plaintext.len() + sealedbox::OVERHEAD_LENGTH];
    sealedbox::encrypt(plaintext, recipient, &mut ciphertext).map_err(|error| match error {
        AlkaliError::SealError(SealError::PublicKeyUnacceptable) => SealingError::InvalidRecipient,
        error => SealingError::Library(error),
    })?;
    Ok(ciphertext)
}

/// Builds an encrypted PCP from prepared inputs and recipient keys.
///
/// The caller supplies authenticated source data, prepared biometrics, authorized
/// recipients and a manifest signer. Run this synchronous operation on a blocking
/// worker when called from an asynchronous service. Call [`validate_build_inputs`]
/// before generating backend keys. Retain `source` until [`crate::verify_completed_pcp`]
/// passes on the opened result. Source Iris files and captures are preserved;
/// face, DI and normalized iris outputs come from `biometrics`.
///
/// # Errors
/// Propagates mapping, archive, encryption and signer failures without returning
/// a partial package.
pub fn build<E>(
    source: &SourcePcp,
    biometrics: &PreparedBiometrics<'_>,
    context: &MigrationContext,
    recipients: OutputRecipients<'_>,
    sign_digest: impl FnOnce(&[u8; 32]) -> Result<Vec<u8>, E>,
) -> Result<orb_pcp::Package, BuildError<E>> {
    validate_user_key(recipients.user_public_key)?;
    let timestamp =
        u32::try_from(context.migrated_ts).map_err(|_| Error::InvalidField("migrated_ts"))?;
    with_prepared_inputs(source, biometrics, context, |info, images, migration| {
        let iris = source.iris()?;
        let di = orb_pcp::Di::embeddings(&biometrics.di_embeddings)
            .shares(biometrics.di_embedding_shares.each_ref())
            .map_err(|_| Error::InvalidField("di_embedding_shares"))?;
        let biometrics = orb_pcp::Biometrics::images(images)
            .iris(iris)
            .di(di)
            .face_embeddings(&biometrics.face_embeddings);
        orb_pcp::Builder::timestamp(timestamp)
            .info(info)
            .user_public_key(recipients.user_public_key)
            .backend_keys(recipients.backend_keys)
            .biometrics(orb_pcp::BiometricPolicy::Included(biometrics))
            // Source Iris files and version fields may be absent. Present payloads
            // are validated by Iris construction; fresh DI is validated separately.
            .strict(false)
            .migration(migration)
            .rng(rand::rngs::OsRng)
            .sealer(seal)
            .signer(sign_digest)
            .build()
            .map_err(BuildError::Build)
    })?
}

/// Checks mapping inputs and the user's encryption key without backend keys.
/// Run this before backend key generation to reject invalid input before remote calls.
/// Building repeats these checks because callers can change inputs between calls.
///
/// # Errors
/// Returns invalid or inconsistent mapping inputs, an unusable recipient key, or
/// a local cryptographic library failure. This does not authenticate the user key.
pub fn validate_build_inputs(
    source: &SourcePcp,
    biometrics: &PreparedBiometrics<'_>,
    context: &MigrationContext,
    user_public_key: &[u8; 32],
) -> Result<(), Error> {
    validate_user_key(user_public_key)?;
    with_prepared_inputs(source, biometrics, context, |_, _, _| ())
}

fn validate_user_key(user_public_key: &[u8; 32]) -> Result<(), Error> {
    // An empty sealed box uses the same recipient checks as package encryption.
    sealedbox::encrypt(&[], user_public_key, &mut [0; sealedbox::OVERHEAD_LENGTH])
        .map(|_| ())
        .map_err(|error| match error {
            AlkaliError::SealError(SealError::PublicKeyUnacceptable) => {
                Error::InvalidField("user_public_key")
            }
            error => Error::RecipientValidation(error),
        })
}

fn with_prepared_inputs<T>(
    source: &SourcePcp,
    biometrics: &PreparedBiometrics<'_>,
    context: &MigrationContext,
    consume: impl FnOnce(&v1::Info, &orb_pcp::PackageImages<'_>, &v1::Migration) -> T,
) -> Result<T, Error> {
    source.validate_iris()?;
    biometrics.validate(source)?;
    nonempty(&context.tee_software_version, "tee_software_version")?;
    nonempty(&context.signing_key_id, "signing_key_id")?;
    u32::try_from(context.migrated_ts).map_err(|_| Error::InvalidField("migrated_ts"))?;
    let signup_id = context.signup_id.to_string();
    if source.info.signup_id.as_deref() == Some(signup_id.as_str()) {
        return Err(Error::InvalidField("signup_id"));
    }
    let info = v1::Info {
        signup_id: Some(signup_id),
        ..source.info.clone()
    };
    let files = &source.files;

    // Claim fixed-name images first, then the multiframe captures.
    let mut used = BTreeSet::new();
    let left_primary = orb_pcp::PrimaryIrisFrame {
        ir_png: image(files, "iris/left_ir.png", &mut used)?,
        normalized: normalized(&biometrics.left_normalized),
    };
    let right_primary = orb_pcp::PrimaryIrisFrame {
        ir_png: image(files, "iris/right_ir.png", &mut used)?,
        normalized: normalized(&biometrics.right_normalized),
    };
    let thumbnail_png = image(files, "face/thumbnail.png", &mut used)?;
    let face_ir_png = optional_image(files, "face_ir_and_thermal/face_ir.png", &mut used);
    let thermal_png = optional_image(files, "face_ir_and_thermal/thermal.png", &mut used);
    let fraud = fraud_images(files, &mut used);
    let mut ids = BTreeSet::new();
    let left_ids = image_ids(&info.left_ir_multiframe_image_ids, &mut ids)?;
    let right_ids = image_ids(&info.right_ir_multiframe_image_ids, &mut ids)?;
    let left_extra = extra_frames(files, &left_ids, &biometrics.extra_normalized, &mut used)?;
    let right_extra = extra_frames(files, &right_ids, &biometrics.extra_normalized, &mut used)?;
    if files.keys().filter(|path| raw_image(path)).count() != used.len() {
        return Err(Error::UnmappedImage);
    }
    let images = orb_pcp::PackageImages {
        left: orb_pcp::IrisEye {
            primary: left_primary,
            multiframe: &left_extra,
        },
        right: orb_pcp::IrisEye {
            primary: right_primary,
            multiframe: &right_extra,
        },
        thumbnail_png: Some(thumbnail_png),
        face_ir_png,
        thermal_png,
        fraud,
    };
    let migration = migration(source, biometrics, context);
    Ok(consume(&info, &images, &migration))
}

/// The `migration.pb` message of this run.
pub(crate) fn migration(
    source: &SourcePcp,
    biometrics: &PreparedBiometrics<'_>,
    context: &MigrationContext,
) -> v1::Migration {
    v1::Migration {
        tee_software_version: Some(context.tee_software_version.clone()),
        src_signup_id: source.info.signup_id.clone(),
        source_pcp_version: Some(source.version.as_str().to_owned()),
        migrated_ts: Some(context.migrated_ts),
        biometric_pipeline_version: Some(biometrics.biometric_pipeline_version.clone()),
        signing_key_id: Some(context.signing_key_id.clone()),
    }
}

/// The source's fraud images, each only if present. Without any, no
/// `fraud.tar` is written.
fn fraud_images<'a>(
    files: &'a Files,
    used: &mut BTreeSet<String>,
) -> Option<orb_pcp::FraudImages<'a>> {
    if !files.keys().any(|path| path.starts_with("fraud/")) {
        return None;
    }
    Some(orb_pcp::FraudImages {
        scc_rgb_png: optional_image(files, "fraud/scc_rgb.png", used),
        left_rgb_png: optional_image(files, "fraud/left_rgb.png", used),
        right_rgb_png: optional_image(files, "fraud/right_rgb.png", used),
        left_thermal_png: optional_image(files, "fraud/left_thermal.png", used),
        right_thermal_png: optional_image(files, "fraud/right_thermal.png", used),
        scc_depth_png: optional_image(files, "fraud/scc_depth.png", used),
        left_depth_png: optional_image(files, "fraud/left_depth.png", used),
        right_depth_png: optional_image(files, "fraud/right_depth.png", used),
    })
}

fn optional_image<'a>(
    files: &'a Files,
    path: &str,
    used: &mut BTreeSet<String>,
) -> Option<&'a [u8]> {
    files.get(path).map(|bytes| {
        used.insert(path.to_owned());
        bytes.as_slice()
    })
}

fn image<'a>(files: &'a Files, path: &str, used: &mut BTreeSet<String>) -> Result<&'a [u8], Error> {
    optional_image(files, path, used)
        .filter(|b| !b.is_empty())
        .ok_or(Error::InvalidField("raw_image"))
}

/// The builder names multiframe files after the typed image ID, so an ID must
/// print back exactly as the source wrote it, and each may appear only once.
fn image_ids(ids: &[String], seen: &mut BTreeSet<String>) -> Result<Vec<ImageId>, Error> {
    ids.iter()
        .map(|id| {
            let parsed = id
                .parse::<ImageId>()
                .ok()
                .filter(|parsed| parsed.to_string() == *id)
                .ok_or(Error::InvalidField("multiframe_image_id"))?;
            if !seen.insert(id.clone()) {
                return Err(Error::InvalidField("duplicate_image_id"));
            }
            Ok(parsed)
        })
        .collect()
}

fn extra_frames<'a>(
    files: &'a Files,
    ids: &'a [ImageId],
    extra_normalized: &'a BTreeMap<String, orb_pcp::NormalizedIrisFrame<'a>>,
    used: &mut BTreeSet<String>,
) -> Result<Vec<orb_pcp::IrisFrame<'a>>, Error> {
    ids.iter()
        .map(|id| {
            let id_text = id.to_string();
            Ok(orb_pcp::IrisFrame {
                image_id: id,
                ir_png: image(files, &format!("iris/{id_text}.png"), used)?,
                normalized: extra_normalized.get(&id_text).map(normalized),
            })
        })
        .collect()
}

fn normalized<'a>(frame: &orb_pcp::NormalizedIrisFrame<'a>) -> orb_pcp::NormalizedIrisFrame<'a> {
    orb_pcp::NormalizedIrisFrame {
        image: frame.image,
        mask: frame.mask,
        image_resized: frame.image_resized,
        mask_resized: frame.mask_resized,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_boxes_preserve_recipient_bytes_and_use_fresh_ephemeral_keys() {
        let mut pair = sealedbox::Keypair::generate().unwrap();
        // X25519 accepts this alias, but sealed-box nonce derivation uses its exact bytes.
        for high_bit in [0, 0x80] {
            pair.public_key[31] = (pair.public_key[31] & 0x7f) | high_bit;
            for plaintext in [b"".as_slice(), b"synthetic payload".as_slice()] {
                let first = seal(plaintext, &pair.public_key).unwrap();
                let second = seal(plaintext, &pair.public_key).unwrap();
                assert_ne!(&first[..32], &second[..32]);
                for ciphertext in [first, second] {
                    assert_eq!(ciphertext.len(), plaintext.len() + 48);
                    let mut opened = vec![0; plaintext.len()];
                    sealedbox::decrypt(&ciphertext, &pair, &mut opened).unwrap();
                    assert_eq!(opened, plaintext);
                }
            }
        }
    }

    #[test]
    fn sealed_boxes_reject_wrong_recipients_and_tampering() {
        let pair = sealedbox::Keypair::generate().unwrap();
        let other = sealedbox::Keypair::generate().unwrap();
        let ciphertext = seal(b"synthetic payload", &pair.public_key).unwrap();
        let mut opened = vec![0; ciphertext.len() - sealedbox::OVERHEAD_LENGTH];
        assert!(sealedbox::decrypt(&ciphertext, &other, &mut opened).is_err());
        for index in 0..ciphertext.len() {
            let mut altered = ciphertext.clone();
            altered[index] ^= 1;
            assert!(sealedbox::decrypt(&altered, &pair, &mut opened).is_err());
        }
        for length in 0..ciphertext.len() {
            assert!(sealedbox::decrypt(&ciphertext[..length], &pair, &mut opened).is_err());
        }
    }
}
