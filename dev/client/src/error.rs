//! The CLI's error type.

use std::{io, path::PathBuf};

/// Failures running a command.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The input file could not be read.
    #[error("could not read {path}")]
    ReadInput {
        /// The file that failed.
        path: PathBuf,
        /// Why.
        #[source]
        source: io::Error,
    },

    /// The output file could not be written.
    #[error("could not write {path}")]
    WriteOutput {
        /// The file that failed.
        path: PathBuf,
        /// Why.
        #[source]
        source: io::Error,
    },

    /// The PCP is larger than the host will accept, caught before sending it.
    #[error("{path} is {bytes} bytes; the host accepts at most {limit}")]
    InputTooLarge {
        /// The file that failed.
        path: PathBuf,
        /// Its size.
        bytes: usize,
        /// What the host accepts.
        limit: usize,
    },

    /// The host URL was not usable.
    #[error("invalid host URL: {0}")]
    InvalidHost(String),

    /// The request never completed.
    #[error("request to the host failed")]
    Request(#[source] reqwest::Error),

    /// A migration is already running.
    ///
    /// Promoted out of [`Self::Api`] because it is the one code with an obvious action: wait
    /// and run the command again.
    #[error("a migration is already running on the host; retry once it finishes")]
    MigrationInProgress,

    /// The host answered with an error envelope.
    #[error("host returned HTTP {status} ({code}): {message}")]
    Api {
        /// The status the host chose.
        status: u16,
        /// Machine-readable code from the envelope.
        code: String,
        /// The host's human-readable message.
        message: String,
        /// Whether the host says the request may be retried.
        allow_retry: bool,
    },

    /// The host answered with a non-success status and no readable envelope.
    #[error("host returned HTTP {0}")]
    Status(u16),
}
