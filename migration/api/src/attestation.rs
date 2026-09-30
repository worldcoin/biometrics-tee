//! Source of the attestation returned by `POST /v1/init-migration`.
//!
//! The migration enclave has no boot sequence yet, so it cannot produce a Nitro attestation
//! document. Until it can, only the opt-in stub below exists and it never runs in production.

#[derive(Clone)]
pub struct Attestation {
    pub enclave_id: String,
    /// COSE attestation document, standard padded base64. Empty while stubbed.
    pub document: String,
}

#[derive(Clone)]
pub struct Attestor {
    enclave_id: String,
}

impl Attestor {
    pub fn stub(enclave_id: String) -> Self {
        Self { enclave_id }
    }

    pub fn attest(&self) -> Attestation {
        Attestation {
            enclave_id: self.enclave_id.clone(),
            document: String::new(),
        }
    }
}
