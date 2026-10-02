//! Generated protobuf contracts, transport framing, and bounded codecs.
//! Request decoding enforces byte limits only; semantic request invariants are checked
//! by the worker.
#![warn(clippy::pedantic)]

pub mod face;
pub mod framing;
pub mod iris;
pub mod protobuf;

#[allow(
    clippy::doc_markdown,
    clippy::struct_field_names,
    clippy::trivially_copy_pass_by_ref,
    clippy::must_use_candidate,
    reason = "prost-generated code"
)]
mod generated {
    pub mod face {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/biometric_engines.face.v1.rs"));
        }
    }
    pub mod iris {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/biometric_engines.iris.v1.rs"));
        }
    }
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/biometric_engines.v1.rs"));
    }
}

pub use generated::v1::*;

/// Version inserted by the envelope constructors and checked by the worker.
pub const PROTOCOL_VERSION: u32 = 1;

impl Request {
    /// Wraps an operation in the current wire version.
    ///
    /// `request_id` must be non-zero: zero is reserved for responses to requests whose
    /// bytes could not be decoded, see [`protobuf::RejectedRequest`].
    #[must_use]
    pub fn new(request_id: u64, operation: request::Operation) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            operation: Some(operation),
        }
    }
}

impl Response {
    /// Wraps a result or failure in the current wire version.
    #[must_use]
    pub fn new(request_id: u64, outcome: response::Outcome) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            outcome: Some(outcome),
        }
    }
}

impl From<face::Failure> for Failure {
    fn from(value: face::Failure) -> Self {
        Self {
            kind: Some(failure::Kind::Face(value)),
        }
    }
}

impl From<iris::Failure> for Failure {
    fn from(value: iris::Failure) -> Self {
        Self {
            kind: Some(failure::Kind::Iris(value)),
        }
    }
}

impl From<protocol_failure::Reason> for Failure {
    fn from(reason: protocol_failure::Reason) -> Self {
        Self {
            kind: Some(failure::Kind::Protocol(ProtocolFailure {
                reason: Some(reason),
            })),
        }
    }
}

impl From<Failure> for response::Outcome {
    fn from(value: Failure) -> Self {
        Self::Failure(value)
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Failure {}

/// Formats a prost enumeration field by variant name, or by raw value if unknown.
pub(crate) fn enum_debug<E: TryFrom<i32> + std::fmt::Debug>(value: i32) -> impl std::fmt::Debug {
    std::fmt::from_fn(move |f| match E::try_from(value) {
        Ok(variant) => std::fmt::Debug::fmt(&variant, f),
        Err(_) => std::fmt::Debug::fmt(&value, f),
    })
}
