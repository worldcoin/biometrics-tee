//! Adapt mapped biometric content to the shared builder's borrowed inputs.

use std::collections::BTreeSet;

use crate::{Error, Files, MappedPcp};

impl MappedPcp<'_> {
    /// Expose the mapped biometric part directly to `orb_pcp::build`.
    ///
    /// The builder requires primary image IDs even when old PCPs lack them.
    /// Missing IDs return an error. This method passes biometric inputs;
    /// capture metadata, migration metadata and legacy members are separate.
    pub fn with_builder_biometrics<T>(
        &self,
        use_inputs: impl FnOnce(orb_pcp::BiometricPolicy<'_>) -> T,
    ) -> Result<T, Error> {
        let mut used = BTreeSet::new();
        let left_primary = orb_pcp::IrisFrame {
            image_id: image_id(self.info.left_ir_image_id.as_deref(), "left_ir_image_id")?,
            ir_png: image(&self.raw_images, "iris/left_ir.png", &mut used)?,
            normalized: Some(normalized(&self.biometrics.left_normalized)),
        };
        let right_primary = orb_pcp::IrisFrame {
            image_id: image_id(self.info.right_ir_image_id.as_deref(), "right_ir_image_id")?,
            ir_png: image(&self.raw_images, "iris/right_ir.png", &mut used)?,
            normalized: Some(normalized(&self.biometrics.right_normalized)),
        };
        let left_extra = extra_frames(
            &self.raw_images,
            self.info.left_ir_multiframe_image_ids.as_deref(),
            &self.biometrics.extra_normalized,
            &mut used,
        )?;
        let right_extra = extra_frames(
            &self.raw_images,
            self.info.right_ir_multiframe_image_ids.as_deref(),
            &self.biometrics.extra_normalized,
            &mut used,
        )?;
        if self.biometrics.extra_normalized.keys().any(|id| {
            !left_extra
                .iter()
                .chain(&right_extra)
                .any(|frame| frame.image_id == id)
        }) {
            return Err(Error::InvalidField("normalized_image_id"));
        }
        let fraud = if self.raw_images.keys().any(|p| p.starts_with("fraud/")) {
            Some(orb_pcp::FraudImages {
                scc_rgb_png: image(&self.raw_images, "fraud/scc_rgb.png", &mut used)?,
                left_rgb_png: image(&self.raw_images, "fraud/left_rgb.png", &mut used)?,
                right_rgb_png: image(&self.raw_images, "fraud/right_rgb.png", &mut used)?,
                left_thermal_png: optional_image(
                    &self.raw_images,
                    "fraud/left_thermal.png",
                    &mut used,
                ),
                right_thermal_png: optional_image(
                    &self.raw_images,
                    "fraud/right_thermal.png",
                    &mut used,
                ),
                scc_depth_png: optional_image(&self.raw_images, "fraud/scc_depth.png", &mut used),
                left_depth_png: optional_image(&self.raw_images, "fraud/left_depth.png", &mut used),
                right_depth_png: optional_image(
                    &self.raw_images,
                    "fraud/right_depth.png",
                    &mut used,
                ),
            })
        } else {
            None
        };
        let images = orb_pcp::PackageImages {
            left: Some(orb_pcp::IrisEye {
                primary: left_primary,
                multiframe: &left_extra,
            }),
            right: Some(orb_pcp::IrisEye {
                primary: right_primary,
                multiframe: &right_extra,
            }),
            thumbnail_png: Some(image(&self.raw_images, "face/thumbnail.png", &mut used)?),
            face_ir_png: optional_image(
                &self.raw_images,
                "face_ir_and_thermal/face_ir.png",
                &mut used,
            ),
            thermal_png: optional_image(
                &self.raw_images,
                "face_ir_and_thermal/thermal.png",
                &mut used,
            ),
            fraud,
        };
        if used.len() != self.raw_images.len() {
            return Err(Error::UnmappedImage);
        }
        let left_aggregate = refs(self.info.left_iris_code_aggregate_image_ids.as_deref());
        let right_aggregate = refs(self.info.right_iris_code_aggregate_image_ids.as_deref());
        Ok(use_inputs(orb_pcp::BiometricPolicy::Included {
            images: &images,
            thumbnail_image_id: Some(image_id(
                self.info.thumbnail_image_id.as_deref(),
                "thumbnail_image_id",
            )?),
            left_iris_code_aggregate_image_ids: &left_aggregate,
            right_iris_code_aggregate_image_ids: &right_aggregate,
            face_embeddings: &self.biometrics.face_embeddings,
            daugman: &self.biometrics.daugman,
            di: Some(&self.biometrics.di),
        }))
    }
}

fn refs(values: Option<&[String]>) -> Vec<&str> {
    values
        .unwrap_or_default()
        .iter()
        .map(String::as_str)
        .collect()
}

fn image_id<'a>(value: Option<&'a str>, field: &'static str) -> Result<&'a str, Error> {
    value
        .filter(|id| !id.is_empty())
        .ok_or(Error::InvalidField(field))
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

fn extra_frames<'a>(
    files: &'a Files,
    ids: Option<&'a [String]>,
    extra_normalized: &'a std::collections::BTreeMap<String, orb_pcp::NormalizedIrisFrame<'a>>,
    used: &mut BTreeSet<String>,
) -> Result<Vec<orb_pcp::IrisFrame<'a>>, Error> {
    ids.unwrap_or_default()
        .iter()
        .map(|id| {
            // An image ID becomes an archive basename in the upstream builder.
            if id.is_empty()
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            {
                return Err(Error::InvalidField("multiframe_image_id"));
            }
            let path = format!("iris/{id}.png");
            if used.contains(&path) {
                return Err(Error::InvalidField("duplicate_image_id"));
            }
            Ok(orb_pcp::IrisFrame {
                image_id: id,
                ir_png: image(files, &path, used)?,
                normalized: extra_normalized.get(id).map(normalized),
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
