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
pub struct OutputRecipients {
    pub user_public_key: [u8; 32],
    pub backend_keys: orb_pcp::BackendKeys,
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
/// Consumes the fresh outputs; source captures are copied into the owned builder.
/// Completion checks require independently retained expected biometric outputs.
///
/// # Errors
/// Propagates mapping, archive, encryption and signer failures without returning
/// a partial package.
pub fn build<E>(
    source: &SourcePcp,
    biometrics: PreparedBiometrics,
    context: &MigrationContext,
    recipients: OutputRecipients,
    sign_digest: impl FnOnce(&[u8; 32]) -> Result<Vec<u8>, E>,
) -> Result<orb_pcp::Package, BuildError<E>> {
    validate_user_key(&recipients.user_public_key)?;
    let timestamp =
        u32::try_from(context.migrated_ts).map_err(|_| Error::InvalidField("migrated_ts"))?;
    validate_mapping(source, &biometrics, context)?;
    let migration = migration(source, &biometrics, context);
    let iris = source.iris()?;
    let info = v1::Info {
        signup_id: Some(context.signup_id.to_string()),
        ..source.info.clone()
    };
    let mut seen = BTreeSet::new();
    let left_ids = image_ids(&info.left_ir_multiframe_image_ids, &mut seen)?;
    let right_ids = image_ids(&info.right_ir_multiframe_image_ids, &mut seen)?;
    let PreparedBiometrics {
        face_embeddings,
        di_embeddings,
        di_embedding_shares,
        orbit5_di_embedding_shares,
        left_normalized,
        right_normalized,
        mut extra_normalized,
        ..
    } = biometrics;
    let files = &source.files;
    let mut used = BTreeSet::new();
    let images = orb_pcp::PackageImages {
        left: orb_pcp::IrisEye {
            primary: orb_pcp::PrimaryIrisFrame {
                ir_png: image(files, "iris/left_ir.png", &mut used)?.to_vec(),
                normalized: left_normalized,
            },
            multiframe: extra_frames(files, left_ids, &mut extra_normalized, &mut used)?,
        },
        right: orb_pcp::IrisEye {
            primary: orb_pcp::PrimaryIrisFrame {
                ir_png: image(files, "iris/right_ir.png", &mut used)?.to_vec(),
                normalized: right_normalized,
            },
            multiframe: extra_frames(files, right_ids, &mut extra_normalized, &mut used)?,
        },
        thumbnail_png: Some(image(files, "face/thumbnail.png", &mut used)?.to_vec()),
        face_ir_png: optional_image(files, "face_ir_and_thermal/face_ir.png", &mut used)
            .map(<[u8]>::to_vec),
        thermal_png: optional_image(files, "face_ir_and_thermal/thermal.png", &mut used)
            .map(<[u8]>::to_vec),
        fraud: fraud_images(files, &mut used),
    };
    if files.keys().filter(|path| raw_image(path)).count() != used.len() {
        return Err(Error::UnmappedImage.into());
    }
    let di = orb_pcp::Di::embeddings(di_embeddings)
        .orbit5_di_embedding_shares(orbit5_di_embedding_shares)
        .shares(di_embedding_shares)
        .map_err(|_| Error::InvalidField("di_embedding_shares"))?;
    let biometrics = orb_pcp::Biometrics::images(images)
        .iris(iris)
        .di(di)
        .face_embeddings(face_embeddings);
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
    biometrics: &PreparedBiometrics,
    context: &MigrationContext,
    user_public_key: &[u8; 32],
) -> Result<(), Error> {
    validate_user_key(user_public_key)?;
    validate_mapping(source, biometrics, context)
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

fn validate_mapping(
    source: &SourcePcp,
    biometrics: &PreparedBiometrics,
    context: &MigrationContext,
) -> Result<(), Error> {
    source.validate_iris()?;
    biometrics.validate(source)?;
    nonempty(&context.tee_software_version, "tee_software_version")?;
    nonempty(&context.signing_key_id, "signing_key_id")?;
    u32::try_from(context.migrated_ts).map_err(|_| Error::InvalidField("migrated_ts"))?;
    if source.info.signup_id.as_deref() == Some(context.signup_id.to_string().as_str()) {
        return Err(Error::InvalidField("signup_id"));
    }
    // Validate every mapped image without allocating copies of its bytes.
    let files = &source.files;
    let mut used = BTreeSet::new();
    for path in [
        "iris/left_ir.png",
        "iris/right_ir.png",
        "face/thumbnail.png",
    ] {
        image(files, path, &mut used)?;
    }
    for path in [
        "face_ir_and_thermal/face_ir.png",
        "face_ir_and_thermal/thermal.png",
        "fraud/scc_rgb.png",
        "fraud/left_rgb.png",
        "fraud/right_rgb.png",
        "fraud/left_thermal.png",
        "fraud/right_thermal.png",
        "fraud/scc_depth.png",
        "fraud/left_depth.png",
        "fraud/right_depth.png",
    ] {
        optional_image(files, path, &mut used);
    }
    let mut seen = BTreeSet::new();
    for ids in [
        &source.info.left_ir_multiframe_image_ids,
        &source.info.right_ir_multiframe_image_ids,
    ] {
        for id in image_ids(ids, &mut seen)? {
            image(files, &format!("iris/{id}.png"), &mut used)?;
        }
    }
    if files.keys().filter(|path| raw_image(path)).count() != used.len() {
        return Err(Error::UnmappedImage);
    }
    Ok(())
}

/// The `migration.pb` message of this run.
pub(crate) fn migration(
    source: &SourcePcp,
    biometrics: &PreparedBiometrics,
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
fn fraud_images(files: &Files, used: &mut BTreeSet<String>) -> Option<orb_pcp::FraudImages> {
    if !files.keys().any(|path| path.starts_with("fraud/")) {
        return None;
    }
    Some(orb_pcp::FraudImages {
        scc_rgb_png: optional_image(files, "fraud/scc_rgb.png", used).map(<[u8]>::to_vec),
        left_rgb_png: optional_image(files, "fraud/left_rgb.png", used).map(<[u8]>::to_vec),
        right_rgb_png: optional_image(files, "fraud/right_rgb.png", used).map(<[u8]>::to_vec),
        left_thermal_png: optional_image(files, "fraud/left_thermal.png", used).map(<[u8]>::to_vec),
        right_thermal_png: optional_image(files, "fraud/right_thermal.png", used)
            .map(<[u8]>::to_vec),
        scc_depth_png: optional_image(files, "fraud/scc_depth.png", used).map(<[u8]>::to_vec),
        left_depth_png: optional_image(files, "fraud/left_depth.png", used).map(<[u8]>::to_vec),
        right_depth_png: optional_image(files, "fraud/right_depth.png", used).map(<[u8]>::to_vec),
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

fn extra_frames(
    files: &Files,
    ids: Vec<ImageId>,
    extra_normalized: &mut BTreeMap<String, orb_pcp::NormalizedIrisFrame>,
    used: &mut BTreeSet<String>,
) -> Result<Vec<orb_pcp::IrisFrame>, Error> {
    ids.into_iter()
        .map(|id| {
            let id_text = id.to_string();
            Ok(orb_pcp::IrisFrame {
                image_id: id,
                ir_png: image(files, &format!("iris/{id_text}.png"), used)?.to_vec(),
                normalized: extra_normalized.remove(&id_text),
            })
        })
        .collect()
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
