use std::str::FromStr;

use serde::{Deserialize, de::IntoDeserializer};

use crate::{BackendKeys, Error, Files, Info, parse_json, validate_files};

/// Source versions accepted by the opened-artifact mapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum SourceVersion {
    #[serde(rename = "0.2")]
    V0_2,
    #[serde(rename = "0.3")]
    V0_3,
    #[serde(rename = "2.0")]
    V2_0,
    #[serde(rename = "2.1")]
    V2_1,
    #[serde(rename = "2.2")]
    V2_2,
    #[serde(rename = "2.3")]
    V2_3,
    #[serde(rename = "2.4")]
    V2_4,
    #[serde(rename = "2.5")]
    V2_5,
    #[serde(rename = "2.6")]
    V2_6,
    #[serde(rename = "2.7")]
    V2_7,
    #[serde(rename = "2.8")]
    V2_8,
}

impl SourceVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V0_2 => "0.2",
            Self::V0_3 => "0.3",
            Self::V2_0 => "2.0",
            Self::V2_1 => "2.1",
            Self::V2_2 => "2.2",
            Self::V2_3 => "2.3",
            Self::V2_4 => "2.4",
            Self::V2_5 => "2.5",
            Self::V2_6 => "2.6",
            Self::V2_7 => "2.7",
            Self::V2_8 => "2.8",
        }
    }
}

impl FromStr for SourceVersion {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::deserialize(value.into_deserializer())
            .map_err(|_: serde::de::value::Error| Error::UnsupportedVersion)
    }
}

// Historical hashes.json files encode the PCP version as either a string or a number.
#[derive(Deserialize)]
#[serde(untagged)]
enum LegacyVersionValue {
    Text(String),
    Number(serde_json::Number),
}

/// Parse structure only; this type is NOT evidence of authenticity.
///
/// The caller must verify source signatures/hashes, authorize ownership, decrypt
/// tiers and open inner archives before using these bytes for a migration.
/// Directory markers are not files. Duplicate members must be rejected upstream.
pub struct SourcePcp {
    pub(crate) version: SourceVersion,
    pub(crate) info: Info,
    pub(crate) backend_keys: Option<BackendKeys>,
    pub(crate) files: Files,
}

impl SourcePcp {
    pub fn parse(files: Files) -> Result<Self, Error> {
        validate_files(&files)?;
        #[derive(Deserialize)]
        struct Manifest {
            version: LegacyVersionValue,
        }
        let manifest: Manifest = parse_json(required(&files, "hashes.json")?, "hashes.json")?;
        let version = match manifest.version {
            LegacyVersionValue::Text(s) => s,
            LegacyVersionValue::Number(n) => n.to_string(),
        };
        let version = version.parse::<SourceVersion>()?;
        let info = parse_json(required(&files, "info.json")?, "info.json")?;
        let backend_keys = files
            .get("backend_keys.json")
            .map(|bytes| parse_json(bytes, "backend_keys.json"))
            .transpose()?;
        if files.contains_key("face_ir_and_thermal.tar") {
            return Err(Error::UnopenedArtifact("face_ir_and_thermal.tar"));
        }
        // A new source artifact needs a deliberate preserve/replace decision.
        if files.keys().any(|path| !known_source_artifact(path)) {
            return Err(Error::UnsupportedArtifact);
        }
        Ok(Self {
            version,
            info,
            backend_keys,
            files,
        })
    }

    pub const fn version(&self) -> SourceVersion {
        self.version
    }
    pub const fn info(&self) -> &Info {
        &self.info
    }
    pub const fn backend_keys(&self) -> Option<&BackendKeys> {
        self.backend_keys.as_ref()
    }

    /// Required image inputs for migration. Missing
    /// and zero-byte placeholders fail. This accessor does not define aggregation.
    ///
    /// These are opened logical paths: `iris.tar` members `left_ir.png` and
    /// `right_ir.png`, and the `face.tar` member `thumbnail.png`. The caller must
    /// decrypt/open those archives and prefix their members with `iris/` or
    /// `face/` first. These logical names apply to every accepted source version.
    /// Extra frames and face IR/thermal images are not substitutes for primaries.
    pub fn pipeline_inputs(&self) -> Result<PipelineInputs<'_>, Error> {
        Ok(PipelineInputs {
            left_ir_png: required(&self.files, "iris/left_ir.png")?,
            right_ir_png: required(&self.files, "iris/right_ir.png")?,
            thumbnail_png: required(&self.files, "face/thumbnail.png")?,
        })
    }
}

/// Borrowed image payloads. The sandbox owns image decoding and geometry checks.
pub struct PipelineInputs<'a> {
    pub left_ir_png: &'a [u8],
    pub right_ir_png: &'a [u8],
    pub thumbnail_png: &'a [u8],
}

pub(crate) fn required<'a>(files: &'a Files, name: &'static str) -> Result<&'a [u8], Error> {
    files
        .get(name)
        .filter(|b| !b.is_empty())
        .map(Vec::as_slice)
        .ok_or(Error::MissingArtifact(name))
}

pub(crate) fn raw_image(path: &str) -> bool {
    // Multi-frame captures retain their names and their source image IDs.
    (path.starts_with("iris/") || path.starts_with("face/") || path.starts_with("fraud/"))
        && path.ends_with(".png")
        || matches!(
            path,
            "face_ir_and_thermal/face_ir.png" | "face_ir_and_thermal/thermal.png"
        )
}

pub(crate) fn normalized_artifact(path: &str) -> bool {
    let Some(name) = path.strip_prefix("normalized_iris/") else {
        return false;
    };
    let Some((prefix, name)) = name.split_once("_normalized_") else {
        return false;
    };
    if prefix.is_empty() || prefix.contains('/') {
        return false;
    }
    let Some(name) = name
        .strip_prefix("image")
        .or_else(|| name.strip_prefix("mask"))
    else {
        return false;
    };
    matches!(
        name,
        ".bin"
            | "_resized.bin"
            | "_commitment.bin"
            | "_commitment_resized.bin"
            | "_blinding_factors.bin"
            | "_blinding_factors_resized.bin"
    )
}

fn known_source_artifact(path: &str) -> bool {
    raw_image(path)
        || normalized_artifact(path)
        || matches!(
            path,
            "info.json"
                | "backend_keys.json"
                | "hashes.json"
                | "hashes.sign"
                | "face_embeddings.json"
                | "iris_codes.json"
                | "iris_code_shares_0.json"
                | "iris_code_shares_1.json"
                | "iris_code_shares_2.json"
                | "di_iris_embeddings.pb"
                | "di_iris_embeddings_shares_0.pb"
                | "di_iris_embeddings_shares_1.pb"
                | "di_iris_embeddings_shares_2.pb"
        )
}

/// Source biometrics and signed manifest retained verbatim under `legacy/`.
pub(crate) fn legacy_artifact(path: &str) -> bool {
    matches!(
        path,
        "hashes.json"
            | "hashes.sign"
            | "iris_codes.json"
            | "iris_code_shares_0.json"
            | "iris_code_shares_1.json"
            | "iris_code_shares_2.json"
            | "di_iris_embeddings.pb"
            | "di_iris_embeddings_shares_0.pb"
            | "di_iris_embeddings_shares_1.pb"
            | "di_iris_embeddings_shares_2.pb"
            | "face_embeddings.json"
    )
}
