//! Turn an opened source and this run's outputs into the shared builder's
//! migration request.

use std::collections::{BTreeMap, BTreeSet};

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

/// Validate one migration run and pass its build request to `build`,
/// normally `orb_pcp::build` with a CSPRNG and the enclave signer.
///
/// `info.json` is the source's with the context's signup ID. Raw images, iris
/// codes and shares come from `source` unchanged; face, DI and normalized iris
/// outputs come from `biometrics`.
/// Fails without calling `build` when the prepared biometrics are incomplete or
/// inconsistent, the context reuses the source signup ID, a multiframe image ID
/// is not a canonical image ID, or a raw image has no builder input. The builder
/// rejects other inputs itself, for example a `migrated_ts` beyond 32-bit seconds
/// (used for its archive headers). Retain `source` until `verify_completed_pcp`
/// has passed on the built package.
pub fn with_build_request<T>(
    source: &SourcePcp,
    biometrics: &PreparedBiometrics<'_>,
    context: &MigrationContext,
    recipients: OutputRecipients<'_>,
    build: impl FnOnce(&orb_pcp::BuildRequest<'_>) -> T,
) -> Result<T, Error> {
    biometrics.validate(source)?;
    nonempty(&context.tee_software_version, "tee_software_version")?;
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
    let request = orb_pcp::BuildRequest {
        timestamp: context.migrated_ts,
        info: &info,
        user_public_key: recipients.user_public_key,
        backend_keys: recipients.backend_keys,
        biometrics: orb_pcp::BiometricPolicy::Included {
            images: &images,
            face_embeddings: &biometrics.face_embeddings,
            iris_codes: source.iris_codes.as_ref(),
            iris_code_shares: source.iris_code_shares.each_ref().map(Option::as_ref),
            di_embeddings: &biometrics.di_embeddings,
            di_embedding_shares: &biometrics.di_embedding_shares,
        },
        migration: Some(&migration),
    };
    Ok(build(&request))
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
