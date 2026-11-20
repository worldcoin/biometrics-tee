//! Environment-specific configuration received once from the parent at bootstrap.

use std::str::FromStr;

use anyhow::{Context, ensure};
use ark_babyjubjub::{EdwardsAffine, Fq};
use di_migration_enclave_primitives::kms;
use serde::Deserialize;
use serde_json::Value;
use world_id_primitives::EdDSAPublicKey;

/// Validated deployment choices, fixed for the life of one enclave boot.
pub struct StartupConfig {
    /// Concrete KMS key used to open and wrap PCP backend private keys.
    pub pcp_kms_key_arn: String,
    /// Concrete KMS key used to sign the migrated PCP manifest.
    pub pcp_kms_signing_key_arn: String,
    /// Credential issuer selected by the deployment.
    pub issuer_pubkey: EdDSAPublicKey,
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
struct ConfigInput {
    pcp_kms_key_arn: String,
    pcp_kms_signing_key_arn: String,
    issuer_pubkey_x: String,
    issuer_pubkey_y: String,
}

impl StartupConfig {
    /// Parses the four required settings without changing the process environment.
    ///
    /// # Errors
    /// Rejects missing or unknown fields, mutable KMS aliases and invalid issuer keys.
    pub fn from_value(value: Value) -> anyhow::Result<Self> {
        let input: ConfigInput =
            serde_json::from_value(value).context("invalid migration startup configuration")?;
        validate_key_arn(&input.pcp_kms_key_arn).context("invalid PCP_KMS_KEY_ARN")?;
        validate_key_arn(&input.pcp_kms_signing_key_arn)
            .context("invalid PCP_KMS_SIGNING_KEY_ARN")?;

        let x = coordinate(&input.issuer_pubkey_x).context("invalid ISSUER_PUBKEY_X")?;
        let y = coordinate(&input.issuer_pubkey_y).context("invalid ISSUER_PUBKEY_Y")?;
        let point = EdwardsAffine { x, y };
        ensure!(
            point.is_on_curve()
                && point.is_in_correct_subgroup_assuming_on_curve()
                && !(x == Fq::from(0_u8) && y == Fq::from(1_u8)),
            "issuer public key must be a nonidentity BabyJubJub subgroup point"
        );

        Ok(Self {
            pcp_kms_key_arn: input.pcp_kms_key_arn,
            pcp_kms_signing_key_arn: input.pcp_kms_signing_key_arn,
            issuer_pubkey: EdDSAPublicKey { pk: point },
        })
    }
}

fn coordinate(input: &str) -> anyhow::Result<Fq> {
    let value =
        Fq::from_str(input).map_err(|()| anyhow::anyhow!("expected a decimal field element"))?;
    ensure!(
        value.to_string() == input,
        "expected a canonical decimal field element"
    );
    Ok(value)
}

fn validate_key_arn(arn: &str) -> anyhow::Result<()> {
    let components: Vec<_> = arn.splitn(6, ':').collect();
    let ["arn", "aws", "kms", region, account, resource] = components.as_slice() else {
        anyhow::bail!("expected a concrete AWS KMS key ARN");
    };
    let key_id = resource.strip_prefix("key/").unwrap_or_default();
    let valid_key_id = (key_id.len() == 36 && uuid::Uuid::parse_str(key_id).is_ok())
        || key_id
            .strip_prefix("mrk-")
            .is_some_and(|id| id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    ensure!(
        kms::hostname(region).is_some()
            && account.len() == 12
            && account.bytes().all(|byte| byte.is_ascii_digit())
            && valid_key_id,
        "expected a concrete AWS KMS key ARN"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use world_id_primitives::EdDSAPrivateKey;

    use super::StartupConfig;

    fn config() -> Value {
        let issuer = EdDSAPrivateKey::from_bytes([7; 32]).public();
        json!({
            "PCP_KMS_KEY_ARN": "arn:aws:kms:eu-central-1:000000000000:key/mrk-a5fdff41687d41a0b02ad9bd1d01529a",
            "PCP_KMS_SIGNING_KEY_ARN": "arn:aws:kms:eu-central-1:000000000000:key/12345678-1234-1234-1234-123456789012",
            "ISSUER_PUBKEY_X": issuer.pk.x.to_string(),
            "ISSUER_PUBKEY_Y": issuer.pk.y.to_string(),
        })
    }

    #[test]
    fn accepts_concrete_keys_and_preserves_the_issuer() {
        let input = config();
        let parsed = StartupConfig::from_value(input.clone()).unwrap();
        assert_eq!(parsed.pcp_kms_key_arn, input["PCP_KMS_KEY_ARN"]);
        assert_eq!(
            parsed.pcp_kms_signing_key_arn,
            input["PCP_KMS_SIGNING_KEY_ARN"]
        );
        assert_eq!(
            parsed.issuer_pubkey.pk.x.to_string(),
            input["ISSUER_PUBKEY_X"]
        );
        assert_eq!(
            parsed.issuer_pubkey.pk.y.to_string(),
            input["ISSUER_PUBKEY_Y"]
        );
    }

    #[test]
    fn requires_exactly_the_four_known_settings() {
        let input = config();
        for field in input.as_object().unwrap().keys() {
            let mut missing = input.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(StartupConfig::from_value(missing).is_err(), "{field}");
        }
        let mut unknown = input;
        unknown["RUST_LOG"] = json!("debug");
        assert!(StartupConfig::from_value(unknown).is_err());
        assert!(StartupConfig::from_value(Value::Null).is_err());
    }

    #[test]
    fn accepts_the_stage_issuer() {
        let mut input = config();
        input["ISSUER_PUBKEY_X"] =
            json!("8764755626041608914298444081069238835505190105048545592330271001420004184714");
        input["ISSUER_PUBKEY_Y"] =
            json!("21113891529244736453398517984414846376859272077465756596625387480138387442766");
        assert!(StartupConfig::from_value(input).is_ok());
    }

    #[test]
    fn rejects_aliases_and_malformed_arns_for_both_keys() {
        for field in ["PCP_KMS_KEY_ARN", "PCP_KMS_SIGNING_KEY_ARN"] {
            for arn in [
                "",
                "alias/self_custody",
                "arn:aws:kms:eu-central-1:000000000000:alias/self_custody",
                "arn:aws:kms:eu-central-1:000000000000:key/",
                "arn:aws:kms:eu-central-1:000000000000:key/not-a-key-id",
                "arn:aws:kms:eu-central-1:000000000000:key/mrk-not-a-key-id",
                "arn:aws:kms:evil.example:000000000000:key/12345678-1234-1234-1234-123456789012",
                "arn:aws:kms:eu-central-1:123:key/12345678-1234-1234-1234-123456789012",
            ] {
                let mut input = config();
                input[field] = json!(arn);
                assert!(StartupConfig::from_value(input).is_err(), "{field}: {arn}");
            }
        }
    }

    #[test]
    fn rejects_invalid_coordinates_and_weak_points() {
        for (x, y) in [
            ("invalid", "1"),
            ("-1", "1"),
            ("00", "1"),
            ("0", "0"),
            ("0", "1"),
        ] {
            let mut input = config();
            input["ISSUER_PUBKEY_X"] = json!(x);
            input["ISSUER_PUBKEY_Y"] = json!(y);
            assert!(StartupConfig::from_value(input).is_err(), "({x}, {y})");
        }
    }
}
