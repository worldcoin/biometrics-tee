use serde::{Deserialize, Serialize};

/// Coarse failure classes; they cross to the untrusted host, so they carry no user data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Error {
    /// The request was malformed, e.g. an empty blob or an unknown payload version.
    InvalidInput,
    /// The blob was not sealed to this boot's key, e.g. it targeted an earlier boot.
    RequestNotOpened,
    /// The enclave failed while producing a response; detail stays in its log.
    Internal,
}
