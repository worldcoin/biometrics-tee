use serde::{Deserialize, Serialize};

/// Errors returned by enclave operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Error {
    /// The request carried no PCP.
    EmptyPcp,
    /// The enclave failed while producing a response; detail stays in its log.
    Internal,
}
