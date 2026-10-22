use std::str::FromStr;

use alkali::asymmetric::seal::curve25519xsalsa20poly1305 as sealedbox;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use orb_pcp_defs::v1;
use serde::{Deserialize, de::IntoDeserializer};
use zeroize::Zeroizing;

use crate::archive::files_from_tar;
use crate::integrity::{JsonObject, Manifest};
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

/// Opens the KMS envelope stored for one source archive key.
#[async_trait::async_trait]
pub trait BackendKeyDecryptor: Send + Sync {
    /// Returns the raw private key without logging or retaining it.
    ///
    /// # Errors
    ///
    /// Returns a payload-free error if the envelope cannot be decrypted.
    async fn decrypt_backend_key(
        &self,
        encrypted_private_key: &[u8],
        archive_role: &'static str,
    ) -> Result<Zeroizing<Vec<u8>>, Error>;
}

/// An opened source package whose artifacts and protected metadata match its
/// manifest. It contains the pipeline images, `signup_id`, `orb_id`, and a
/// signature. Optional content must match the manifest when present.
/// The signature's authenticity must be verified separately against a trusted key.
pub struct SourcePcp {
    pub(crate) version: SourceVersion,
    pub(crate) info: v1::Info,
    pub(crate) iris_codes: Option<v1::IrisCodes>,
    pub(crate) iris_code_shares: [Option<v1::IrisCodeShares>; 3],
    pub(crate) files: Files,
}

impl SourcePcp {
    /// Verifies an encrypted source PCP, unwraps its backend keys, and opens its
    /// encrypted inner archives before mapping their members to logical paths.
    ///
    /// The backend key envelope is checked against the manifest before KMS is
    /// called. The full manifest covers the opened inner members, not their
    /// encrypted archives, so it is checked after decryption. Each unwrapped
    /// private key must match the public key in `backend_keys.json`.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed packages, failed KMS unwraps, mismatched
    /// key pairs, failed archive decryption, or unsafe/duplicate archive members.
    pub async fn parse(
        mut files: Files,
        decryptor: &impl BackendKeyDecryptor,
    ) -> Result<Self, Error> {
        validate_source_files(&files)?;
        let manifest = Manifest::parse(required(&files, "hashes.json")?)?;
        required(&files, "hashes.sign")?;
        let info: JsonObject = parse_json(required(&files, "info.json")?, "info.json")?;
        validate_capture_fields(&info)?;
        let backend_keys_bytes = required(&files, "backend_keys.json")?;
        manifest.verify_file("backend_keys.json", backend_keys_bytes)?;
        let backend_keys: v1::BackendKeys = parse_json(backend_keys_bytes, "backend_keys.json")?;
        for &(archive_name, role) in &ARCHIVES {
            let Some(ciphertext) = files.remove(archive_name) else {
                continue;
            };
            let directory = archive_name
                .strip_suffix(".tar")
                .ok_or(Error::InvalidArchive)?;
            let members = open_archive(ciphertext, role, &backend_keys, decryptor).await?;
            insert_archive_members(&mut files, directory, members)?;
        }
        manifest.verify(&files, &info)?;
        Self::from_opened_files(files, manifest.version)
    }

    fn from_opened_files(files: Files, version: SourceVersion) -> Result<Self, Error> {
        validate_source_files(&files)?;
        for path in PIPELINE_IMAGES {
            required(&files, path)?;
        }
        let info_bytes = required(&files, "info.json")?;
        let info: v1::Info = parse_json::<SourceInfo>(info_bytes, "info.json")?.into();
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

fn validate_source_files(files: &Files) -> Result<(), Error> {
    validate_files(files)?;
    if files.keys().any(|path| !known_source_artifact(path)) {
        return Err(Error::UnsupportedArtifact);
    }
    Ok(())
}

async fn open_archive(
    ciphertext: Vec<u8>,
    role: &'static str,
    backend_keys: &v1::BackendKeys,
    decryptor: &impl BackendKeyDecryptor,
) -> Result<Files, Error> {
    let backend_key = backend_key(backend_keys, role).ok_or(Error::InvalidBackendKey(role))?;
    let public_key = decode_key_field(backend_key.public_key.as_deref(), role)?;
    let encrypted_private_key =
        decode_key_field(backend_key.encrypted_private_key.as_deref(), role)?;
    let private_key = decryptor
        .decrypt_backend_key(&encrypted_private_key, role)
        .await?;
    let keypair = keypair(&private_key, &public_key, role)?;

    let plaintext_length = ciphertext
        .len()
        .checked_sub(sealedbox::OVERHEAD_LENGTH)
        .ok_or(Error::ArchiveDecryption(role))?;
    let mut plaintext = Zeroizing::new(vec![0; plaintext_length]);
    sealedbox::decrypt(&ciphertext, &keypair, &mut plaintext)
        .map_err(|_| Error::ArchiveDecryption(role))?;
    files_from_tar(&plaintext)
}

fn insert_archive_members(files: &mut Files, directory: &str, members: Files) -> Result<(), Error> {
    for (member, bytes) in members {
        if files
            .insert(format!("{directory}/{member}"), bytes)
            .is_some()
        {
            return Err(Error::InvalidArchive);
        }
    }
    Ok(())
}

fn validate_capture_fields(info: &JsonObject) -> Result<(), Error> {
    for field in ["signup_id", "orb_id"] {
        if info
            .0
            .get(field)
            .is_none_or(|value| value.is_null() || value.as_str().is_some_and(str::is_empty))
        {
            return Err(Error::MissingCaptureField(field));
        }
    }
    Ok(())
}

fn backend_key<'a>(keys: &'a v1::BackendKeys, role: &str) -> Option<&'a v1::BackendKey> {
    match role {
        "iris" => keys.iris.as_ref(),
        "normalized_iris" => keys.normalized_iris.as_ref(),
        "face" => keys.face.as_ref(),
        "tier2" => keys.tier2.as_ref(),
        _ => None,
    }
}

fn decode_key_field(value: Option<&str>, role: &'static str) -> Result<Vec<u8>, Error> {
    let value = value
        .filter(|value| !value.is_empty())
        .ok_or(Error::InvalidBackendKey(role))?;
    STANDARD
        .decode(value)
        .map_err(|_| Error::InvalidBackendKey(role))
}

fn keypair(
    private_key: &[u8],
    public_key: &[u8],
    role: &'static str,
) -> Result<sealedbox::Keypair, Error> {
    if private_key.len() != sealedbox::PRIVATE_KEY_LENGTH
        || public_key.len() != sealedbox::PUBLIC_KEY_LENGTH
    {
        return Err(Error::InvalidBackendKey(role));
    }
    let mut private =
        sealedbox::PrivateKey::new_empty().map_err(|_| Error::InvalidBackendKey(role))?;
    private.copy_from_slice(private_key);
    let keypair = sealedbox::Keypair::from_private_key(&private)
        .map_err(|_| Error::InvalidBackendKey(role))?;
    if keypair.public_key.as_slice() != public_key {
        return Err(Error::BackendKeyMismatch(role));
    }
    Ok(keypair)
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

const ARCHIVES: [(&str, &str); 5] = [
    ("iris.tar", "iris"),
    ("normalized_iris.tar", "normalized_iris"),
    ("face.tar", "face"),
    ("fraud.tar", "face"),
    ("face_ir_and_thermal.tar", "tier2"),
];

fn known_source_artifact(path: &str) -> bool {
    raw_image(path)
        || normalized_artifact(path)
        || IRIS_CODE_FILES.contains(&path)
        || REPLACED_OUTPUTS.contains(&path)
        || ARCHIVES.iter().any(|(archive, _)| path == *archive)
        // The manifest covers source hashes; signature authentication is external.
        // Backend keys open the source's inner archives.
        || matches!(
            path,
            "info.json" | "hashes.json" | "hashes.sign" | "backend_keys.json"
        )
}

#[cfg(test)]
mod tests;
