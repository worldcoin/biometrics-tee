//! Parent vsock ports and the regional endpoint for the enclave's KMS access.
//!
//! The host forwards [`TLS_PORT`] to the regional KMS endpoint with `pontifex::proxy` and serves
//! its temporary credentials on [`CREDENTIALS_PORT`] with `pontifex::aws_credentials`.

/// Parent port forwarding opaque TLS to the configured regional KMS endpoint.
pub const TLS_PORT: u32 = 7000;
/// Parent port serving temporary credentials only to its configured enclave CID.
pub const CREDENTIALS_PORT: u32 = 7001;

/// Regional AWS KMS hostname; region input cannot supply a URL or port.
#[must_use]
pub fn hostname(region: &str) -> Option<String> {
    if region.len() > 32
        || region.is_empty()
        || !region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return None;
    }
    Some(format!("kms.{region}.amazonaws.com"))
}

#[cfg(test)]
mod tests {
    use super::hostname;

    #[test]
    fn endpoints_are_fixed_aws_hostnames() {
        assert_eq!(
            hostname("us-east-1").unwrap(),
            "kms.us-east-1.amazonaws.com"
        );
        for region in ["", "evil.example", "us-east-1:443", "../", "us-east-1\n"] {
            assert!(hostname(region).is_none());
        }
    }
}
