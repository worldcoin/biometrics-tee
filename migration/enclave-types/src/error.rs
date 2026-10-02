use serde::{Deserialize, Serialize};

/// Coarse failure classes; they cross to the untrusted host, so they carry no user data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Error {
    /// The request was malformed, e.g. an empty blob.
    InvalidInput,
    /// The enclave failed while producing a response; detail stays in its log.
    Internal,
}
