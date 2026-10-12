//! Consistency of opened source bytes with the supplied manifest. Authenticating
//! the manifest requires a separate signature check against a trusted key.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Deserializer, de};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{Error, Files, SourceVersion, parse_json};

/// JSON objects whose top-level names are unique, including fields the mapper
/// does not retain. Salted metadata values are scalars, not nested JSON.
pub(crate) struct JsonObject(pub BTreeMap<String, Value>);

impl<'de> Deserialize<'de> for JsonObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = JsonObject;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object with unique keys")
            }

            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut entries = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, Value>()? {
                    if entries.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate object key"));
                    }
                }
                Ok(JsonObject(entries))
            }
        }

        deserializer.deserialize_map(Visitor)
    }
}

pub(crate) struct Manifest {
    pub version: SourceVersion,
    hashes: BTreeMap<String, String>,
}

impl Manifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let JsonObject(mut entries) = parse_json(bytes, "hashes.json")?;
        let version = match entries.remove("version") {
            Some(Value::String(version)) => version.parse()?,
            // Restrict numeric versions to the formats that used them:
            // converting 2.10 to a number loses its distinction from 2.1.
            Some(Value::Number(version)) => match version.to_string().as_str() {
                "0.2" => SourceVersion::V0_2,
                "0.3" => SourceVersion::V0_3,
                _ => return Err(Error::UnsupportedVersion),
            },
            _ => return Err(Error::SourceIntegrity("manifest_version_invalid")),
        };
        let hashes = entries
            .into_iter()
            .map(|(name, value)| {
                let Value::String(hash) = value else {
                    return Err(Error::SourceIntegrity("manifest_digest_invalid"));
                };
                if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(Error::SourceIntegrity("manifest_digest_invalid"));
                }
                Ok((name, hash))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { version, hashes })
    }

    pub fn verify(&self, files: &Files, info: &JsonObject) -> Result<(), Error> {
        let mut expected = BTreeMap::new();
        for &name in SALTED_FIELDS {
            let value = info.0.get(name).filter(|value| !value.is_null());
            let salt = info
                .0
                .get(&format!("{name}_salt"))
                .filter(|value| !value.is_null());
            let Some(value) = value else {
                if salt.is_some() {
                    return Err(Error::SourceIntegrity("metadata_salt_without_value"));
                }
                continue;
            };
            let text = match value {
                Value::String(text) => text.clone(),
                Value::Number(number) if name == "timestamp" && number.is_u64() => {
                    number.to_string()
                }
                _ => return Err(Error::SourceIntegrity("metadata_value_invalid")),
            };
            let salt = salt
                .and_then(Value::as_str)
                .filter(|salt| !salt.is_empty())
                .ok_or(Error::SourceIntegrity("metadata_salt_invalid"))?;
            let mut hash = Sha256::new();
            hash.update(text.as_bytes());
            hash.update(salt.as_bytes());
            expected.insert(name, format!("{:x}", hash.finalize()));
        }
        for (path, bytes) in files {
            if matches!(path.as_str(), "info.json" | "hashes.json" | "hashes.sign") {
                continue;
            }
            let name = path.rsplit('/').next().unwrap_or(path);
            if expected
                .insert(name, format!("{:x}", Sha256::digest(bytes)))
                .is_some()
            {
                return Err(Error::SourceIntegrity("manifest_name_duplicate"));
            }
        }
        for (name, hash) in &expected {
            match self.hashes.get(*name) {
                None => return Err(Error::SourceIntegrity("manifest_entry_missing")),
                Some(actual) if !actual.eq_ignore_ascii_case(hash) => {
                    return Err(Error::SourceIntegrity("manifest_hash_mismatch"));
                }
                Some(_) => {}
            }
        }
        if self.hashes.len() != expected.len() {
            return Err(Error::SourceIntegrity("manifest_entry_unexpected"));
        }
        Ok(())
    }
}

/// Protected capture fields. Present values require both a salt and a manifest
/// entry; absent or null values have neither. Other metadata is not hash-covered.
const SALTED_FIELDS: &[&str] = &[
    "signup_id",
    "signup_reason",
    "orb_id",
    "operator_id",
    "timestamp",
    "qr_code",
    "id_commitment",
    "software_version",
    "orb_country",
    "device_public_key",
];
