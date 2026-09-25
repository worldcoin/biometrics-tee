//! World ID 4.x (WIP-103) ownership proofs against
//! world-id-proof-verification-service.
//!
//! This crate is a proxy, as signup-service is for v3: the app gets a challenge
//! from the public generator and sends only its id, so the nonce never crosses
//! this process.

mod auth;
mod client;
mod header;
mod verifier;

pub use auth::{AuthError, AuthProvider, JwtAuthProvider};
pub use client::{
    Client, Config, DEFAULT_CHALLENGE_TYPE, Error, FailureClass, ProofVerificationClient,
    VERIFY_PATH, Verdict, VerificationRequest, VerifyResult,
};
pub use header::{MAX_CREDENTIAL_SUB_BYTES, ProofVerificationError};
pub use verifier::{Config as VerifierConfig, Verifier};
