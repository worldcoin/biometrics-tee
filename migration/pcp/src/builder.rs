//! Turn an opened source and this run's outputs into the shared builder's
//! migration request.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime};

use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::mapping::{nonempty, signup_ids};
use crate::source::{raw_image, required};
use crate::{Error, Files, Info, MigrationContext, PreparedBiometrics, SourcePcp};

/// The PCP version of migrated packages: the version the shared builder accepts
/// migration provenance for.
pub const OUTPUT_VERSION: orb_pcp::PcpVersion = orb_pcp::PcpVersion::V2_9;

/// Recipient keys for the new package: the user key encrypts the tiers, the
/// backend keys encrypt the inner archives and are written to `backend_keys.json`.
pub struct OutputRecipients<'a> {
    pub user_public_key: &'a [u8; 32],
    pub backend_keys: orb_pcp::BackendKeys<'a>,
}

/// Validate one migration run and pass its build request to `build`,
/// normally `orb_pcp::build` with a CSPRNG and the enclave signer.
///
/// Capture metadata, raw images and `legacy/` files are read from the opened
/// `source`; the new signup ID is derived from it and the DI model version.
/// Fails without calling `build` when the source lacks a required image or a
/// capture field the builder requires, the prepared biometrics are incomplete or
/// inconsistent, the certificate is not canonical Base64, or an image has no
/// builder input or would collide with another archive member. The builder
/// rejects other inputs itself, for example a `migrated_ts` beyond 32-bit
/// seconds (used for its archive headers). Retain `source` until
/// `verify_completed_pcp` has passed on the built package.
pub fn with_build_request<T>(
    source: &SourcePcp,
    biometrics: &PreparedBiometrics<'_>,
    context: &MigrationContext,
    recipients: OutputRecipients<'_>,
    build: impl FnOnce(&orb_pcp::BuildRequest<'_>) -> T,
) -> Result<T, Error> {
    source.pipeline_inputs()?;
    biometrics.validate(source)?;
    nonempty(&context.tee_version, "tee_version")?;
    let (source_signup_id, signup_id) = signup_ids(source, biometrics)?;
    let (info, files) = (&source.info, &source.files);
    // STANDARD decoding is canonical-only, so the builder's padded Base64
    // re-encoding reproduces the source string.
    let certificate = info
        .orb_public_key_certificate
        .as_deref()
        .map(|text| STANDARD.decode(text))
        .transpose()
        .map_err(|_| Error::InvalidField("orb_public_key_certificate"))?;

    // Claim fixed-name images first so multiframe IDs cannot reuse their names.
    let mut used = BTreeSet::new();
    let left_primary = orb_pcp::IrisFrame {
        image_id: info.left_ir_image_id.as_deref(),
        ir_png: image(files, "iris/left_ir.png", &mut used)?,
        normalized: Some(normalized(&biometrics.left_normalized)),
    };
    let right_primary = orb_pcp::IrisFrame {
        image_id: info.right_ir_image_id.as_deref(),
        ir_png: image(files, "iris/right_ir.png", &mut used)?,
        normalized: Some(normalized(&biometrics.right_normalized)),
    };
    let thumbnail_png = image(files, "face/thumbnail.png", &mut used)?;
    let face_ir_png = optional_image(files, "face_ir_and_thermal/face_ir.png", &mut used);
    let thermal_png = optional_image(files, "face_ir_and_thermal/thermal.png", &mut used);
    let fraud = fraud_images(files, &mut used)?;
    let left_extra = extra_frames(
        files,
        info.left_ir_multiframe_image_ids.as_deref(),
        &biometrics.extra_normalized,
        &mut used,
    )?;
    let right_extra = extra_frames(
        files,
        info.right_ir_multiframe_image_ids.as_deref(),
        &biometrics.extra_normalized,
        &mut used,
    )?;
    if files.keys().filter(|path| raw_image(path)).count() != used.len() {
        return Err(Error::UnmappedImage);
    }
    let images = orb_pcp::PackageImages {
        left: Some(orb_pcp::IrisEye {
            primary: left_primary,
            multiframe: &left_extra,
        }),
        right: Some(orb_pcp::IrisEye {
            primary: right_primary,
            multiframe: &right_extra,
        }),
        thumbnail_png: Some(thumbnail_png),
        face_ir_png,
        thermal_png,
        fraud,
    };
    let left_aggregate = refs(info.left_iris_code_aggregate_image_ids.as_deref());
    let right_aggregate = refs(info.right_iris_code_aggregate_image_ids.as_deref());
    let request = orb_pcp::BuildRequest {
        version: OUTPUT_VERSION,
        timestamp: context.migrated_ts,
        info: package_info(info, &signup_id, certificate.as_deref())?,
        user_public_key: recipients.user_public_key,
        backend_keys: recipients.backend_keys,
        biometrics: orb_pcp::BiometricPolicy::Included {
            images: &images,
            thumbnail_image_id: info.thumbnail_image_id.as_deref(),
            left_iris_code_aggregate_image_ids: &left_aggregate,
            right_iris_code_aggregate_image_ids: &right_aggregate,
            face_embeddings: &biometrics.face_embeddings,
            daugman: &biometrics.daugman,
            di: Some(&biometrics.di),
        },
        migration: Some(orb_pcp::MigrationProvenance {
            tee_version: &context.tee_version,
            src_signup_id: source_signup_id,
            source_pcp_version: source.version.as_str(),
            migrated_ts: context.migrated_ts,
            biometric_pipeline_version: &biometrics.biometric_pipeline_version,
            legacy: legacy_artifacts(files)?,
        }),
    };
    Ok(build(&request))
}

/// Source capture metadata with the new signup ID. Missing values the builder
/// requires fail rather than receiving placeholders. Source salts are not used:
/// the builder generates a fresh salt for every salted value.
fn package_info<'a>(
    info: &'a Info,
    signup_id: &'a str,
    certificate: Option<&'a [u8]>,
) -> Result<orb_pcp::PackageInfo<'a>, Error> {
    let capture_field = |value: &'a Option<String>, field| {
        value.as_deref().ok_or(Error::MissingCaptureField(field))
    };
    let capture_start = capture_field(&info.timestamp, "timestamp")?
        .parse()
        .ok()
        .and_then(|seconds| SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds)))
        .ok_or(Error::InvalidField("timestamp"))?;
    Ok(orb_pcp::PackageInfo {
        signup_id,
        signup_reason: capture_field(&info.signup_reason, "signup_reason")?,
        orb_id: capture_field(&info.orb_id, "orb_id")?,
        operator_id: capture_field(&info.operator_id, "operator_id")?,
        capture_start,
        qr_code: info.qr_code.as_deref(),
        id_commitment: info.id_commitment.as_deref(),
        software_version: info.software_version.as_deref(),
        orb_country: info.orb_country.as_deref(),
        orb_public_key_certificate: certificate,
        device_public_key: info.device_public_key.as_deref(),
    })
}

/// The source files kept verbatim under `legacy/`.
fn legacy_artifacts(files: &Files) -> Result<orb_pcp::LegacyArtifacts<'_>, Error> {
    let get = |name: &str| files.get(name).map(Vec::as_slice);
    Ok(orb_pcp::LegacyArtifacts {
        hashes_json: required(files, "hashes.json")?,
        hashes_sign: required(files, "hashes.sign")?,
        face_embeddings_json: get("face_embeddings.json"),
        iris_codes_json: get("iris_codes.json"),
        iris_code_shares_json: [
            "iris_code_shares_0.json",
            "iris_code_shares_1.json",
            "iris_code_shares_2.json",
        ]
        .map(get),
        di_iris_embeddings_pb: get("di_iris_embeddings.pb"),
        di_iris_embeddings_shares_pb: [
            "di_iris_embeddings_shares_0.pb",
            "di_iris_embeddings_shares_1.pb",
            "di_iris_embeddings_shares_2.pb",
        ]
        .map(get),
    })
}

/// The builder requires all three RGB images whenever any fraud image exists.
fn fraud_images<'a>(
    files: &'a Files,
    used: &mut BTreeSet<String>,
) -> Result<Option<orb_pcp::FraudImages<'a>>, Error> {
    if !files.keys().any(|path| path.starts_with("fraud/")) {
        return Ok(None);
    }
    Ok(Some(orb_pcp::FraudImages {
        scc_rgb_png: image(files, "fraud/scc_rgb.png", used)?,
        left_rgb_png: image(files, "fraud/left_rgb.png", used)?,
        right_rgb_png: image(files, "fraud/right_rgb.png", used)?,
        left_thermal_png: optional_image(files, "fraud/left_thermal.png", used),
        right_thermal_png: optional_image(files, "fraud/right_thermal.png", used),
        scc_depth_png: optional_image(files, "fraud/scc_depth.png", used),
        left_depth_png: optional_image(files, "fraud/left_depth.png", used),
        right_depth_png: optional_image(files, "fraud/right_depth.png", used),
    }))
}

fn refs(values: Option<&[String]>) -> Vec<&str> {
    values
        .unwrap_or_default()
        .iter()
        .map(String::as_str)
        .collect()
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

/// Longest member-name suffix the builder derives from a multiframe image ID.
const LONGEST_NORMALIZED_SUFFIX: &str = "_normalized_image_blinding_factors_resized.bin";
/// The builder's tar member name limit.
const MAX_MEMBER_NAME: usize = 100;

/// The builder names archive members after multiframe image IDs and hashes all
/// members in one manifest namespace, so their names must be unique across
/// archives. Call after claiming every fixed-name image.
fn extra_frames<'a>(
    files: &'a Files,
    ids: Option<&'a [String]>,
    extra_normalized: &'a BTreeMap<String, orb_pcp::NormalizedIrisFrame<'a>>,
    used: &mut BTreeSet<String>,
) -> Result<Vec<orb_pcp::IrisFrame<'a>>, Error> {
    ids.unwrap_or_default()
        .iter()
        .map(|id| {
            let frame_normalized = extra_normalized.get(id);
            let png = format!("{id}.png");
            let longest = match frame_normalized {
                Some(_) => id.len() + LONGEST_NORMALIZED_SUFFIX.len(),
                None => png.len(),
            };
            if id.is_empty()
                || longest > MAX_MEMBER_NAME
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            {
                return Err(Error::InvalidField("multiframe_image_id"));
            }
            // Normalized primaries are named after their eye (`left_normalized_*`).
            if used
                .iter()
                .any(|path| path.rsplit('/').next() == Some(png.as_str()))
                || (frame_normalized.is_some() && matches!(id.as_str(), "left" | "right"))
            {
                return Err(Error::InvalidField("duplicate_image_id"));
            }
            Ok(orb_pcp::IrisFrame {
                image_id: Some(id),
                ir_png: image(files, &format!("iris/{png}"), used)?,
                normalized: frame_normalized.map(normalized),
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
