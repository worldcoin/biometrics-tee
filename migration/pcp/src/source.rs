use std::str::FromStr;

use orb_pcp_defs::v1;
use serde::{Deserialize, de::IntoDeserializer};

use crate::{Error, Files, parse_json, validate_files};

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

// Historical hashes.json files encode the PCP version as a string, or as a
// number in 0.2 and 0.3.
#[derive(Deserialize)]
#[serde(untagged)]
enum LegacyVersionValue {
    Text(String),
    Number(serde_json::Number),
}

/// An opened source package that has everything a migration requires: the raw
/// iris and face images the pipeline reads, `signup_id`, `orb_id`, and the
/// signed manifest. Everything else is optional and carried over when present.
pub struct SourcePcp {
    pub(crate) version: SourceVersion,
    pub(crate) info: v1::Info,
    pub(crate) iris_codes: Option<v1::IrisCodes>,
    pub(crate) iris_code_shares: [Option<v1::IrisCodeShares>; 3],
    pub(crate) files: Files,
}

impl SourcePcp {
    /// Parse an opened source. Inner-archive members use logical paths: the
    /// `iris.tar` member `left_ir.png` is `iris/left_ir.png`, and so on.
    ///
    /// `info.json` fields that the shared `pcp.v1.Info` message does not define
    /// are dropped. Missing and `null` fields read as unset.
    pub fn parse(files: Files) -> Result<Self, Error> {
        validate_files(&files)?;
        #[derive(Deserialize)]
        struct Manifest {
            version: LegacyVersionValue,
        }
        let manifest: Manifest = parse_json(required(&files, "hashes.json")?, "hashes.json")?;
        let version = match manifest.version {
            LegacyVersionValue::Text(s) => s.parse()?,
            // A number is rendered as the shortest float, so restrict it to the
            // versions that used numbers; `2.10` would otherwise become `2.1`.
            LegacyVersionValue::Number(n) => match n.to_string().as_str() {
                "0.2" => SourceVersion::V0_2,
                "0.3" => SourceVersion::V0_3,
                _ => return Err(Error::UnsupportedVersion),
            },
        };
        required(&files, "hashes.sign")?;
        if files.contains_key("face_ir_and_thermal.tar") {
            return Err(Error::UnopenedArtifact("face_ir_and_thermal.tar"));
        }
        // A new source artifact needs a deliberate carry-over or replace decision.
        if files.keys().any(|path| !known_source_artifact(path)) {
            return Err(Error::UnsupportedArtifact);
        }
        for path in PIPELINE_IMAGES {
            required(&files, path)?;
        }
        let info: v1::Info =
            parse_json::<SourceInfo>(required(&files, "info.json")?, "info.json")?.into();
        for (field, value) in [("signup_id", &info.signup_id), ("orb_id", &info.orb_id)] {
            if value.as_deref().is_none_or(str::is_empty) {
                return Err(Error::MissingCaptureField(field));
            }
        }
        let iris_codes = optional_json(&files, "iris_codes.json")?;
        let iris_code_shares = [
            optional_json(&files, "iris_code_shares_0.json")?,
            optional_json(&files, "iris_code_shares_1.json")?,
            optional_json(&files, "iris_code_shares_2.json")?,
        ];
        Ok(Self {
            version,
            info,
            iris_codes,
            iris_code_shares,
            files,
        })
    }

    pub const fn version(&self) -> SourceVersion {
        self.version
    }
    pub const fn info(&self) -> &v1::Info {
        &self.info
    }

    /// The images the biometric pipeline reads: the `iris.tar` members
    /// `left_ir.png` and `right_ir.png`, and the `face.tar` member `thumbnail.png`.
    /// Extra frames and face IR/thermal images are not substitutes for these.
    pub fn pipeline_inputs(&self) -> PipelineInputs<'_> {
        let [left_ir_png, right_ir_png, thumbnail_png] =
            PIPELINE_IMAGES.map(|path| self.files[path].as_slice());
        PipelineInputs {
            left_ir_png,
            right_ir_png,
            thumbnail_png,
        }
    }
}

/// Borrowed image payloads. The sandbox owns image decoding and geometry checks.
pub struct PipelineInputs<'a> {
    pub left_ir_png: &'a [u8],
    pub right_ir_png: &'a [u8],
    pub thumbnail_png: &'a [u8],
}

/// Source capture metadata in the shared message. Two encodings differ from it:
/// 0.2 and 0.3 store the capture time as an integer, and the shared message
/// rejects `null` for a list.
#[derive(Deserialize)]
struct SourceInfo {
    #[serde(default, deserialize_with = "timestamp")]
    timestamp: Option<String>,
    #[serde(default)]
    left_ir_multiframe_image_ids: Option<Vec<String>>,
    #[serde(default)]
    right_ir_multiframe_image_ids: Option<Vec<String>>,
    #[serde(default)]
    left_iris_code_aggregate_image_ids: Option<Vec<String>>,
    #[serde(default)]
    right_iris_code_aggregate_image_ids: Option<Vec<String>>,
    #[serde(flatten)]
    rest: v1::Info,
}

impl From<SourceInfo> for v1::Info {
    fn from(source: SourceInfo) -> Self {
        Self {
            timestamp: source.timestamp,
            left_ir_multiframe_image_ids: source.left_ir_multiframe_image_ids.unwrap_or_default(),
            right_ir_multiframe_image_ids: source.right_ir_multiframe_image_ids.unwrap_or_default(),
            left_iris_code_aggregate_image_ids: source
                .left_iris_code_aggregate_image_ids
                .unwrap_or_default(),
            right_iris_code_aggregate_image_ids: source
                .right_iris_code_aggregate_image_ids
                .unwrap_or_default(),
            ..source.rest
        }
    }
}

/// Unix seconds as a JSON integer (0.2, 0.3) or a string, kept as decimal text.
fn timestamp<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Timestamp {
        Integer(u64),
        Text(String),
    }
    Ok(
        Option::<Timestamp>::deserialize(deserializer)?.map(|value| match value {
            Timestamp::Integer(n) => n.to_string(),
            Timestamp::Text(text) => text,
        }),
    )
}

fn optional_json<T: serde::de::DeserializeOwned>(
    files: &Files,
    name: &'static str,
) -> Result<Option<T>, Error> {
    files
        .get(name)
        .map(|bytes| parse_json(bytes, name))
        .transpose()
}

pub(crate) fn required<'a>(files: &'a Files, name: &'static str) -> Result<&'a [u8], Error> {
    files
        .get(name)
        .filter(|b| !b.is_empty())
        .map(Vec::as_slice)
        .ok_or(Error::MissingArtifact(name))
}

/// The images the biometric pipeline reads; a source without them cannot migrate.
const PIPELINE_IMAGES: [&str; 3] = [
    "iris/left_ir.png",
    "iris/right_ir.png",
    "face/thumbnail.png",
];

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

/// Source iris codes and shares, carried into the new package unchanged when
/// present.
pub(crate) const IRIS_CODE_FILES: [&str; 4] = [
    "iris_codes.json",
    "iris_code_shares_0.json",
    "iris_code_shares_1.json",
    "iris_code_shares_2.json",
];

/// Source outputs this run replaces with fresh ones, together with the
/// normalized iris files.
const REPLACED_OUTPUTS: [&str; 5] = [
    "face_embeddings.json",
    "di_iris_embeddings.pb",
    "di_iris_embeddings_shares_0.pb",
    "di_iris_embeddings_shares_1.pb",
    "di_iris_embeddings_shares_2.pb",
];

fn known_source_artifact(path: &str) -> bool {
    raw_image(path)
        || normalized_artifact(path)
        || IRIS_CODE_FILES.contains(&path)
        || REPLACED_OUTPUTS.contains(&path)
        // The manifest and signature authenticate the source; the backend keys
        // only open its inner archives, which the new package replaces.
        || matches!(
            path,
            "info.json" | "hashes.json" | "hashes.sign" | "backend_keys.json"
        )
}
