//! Metrics for the enclave's KMS access through `pontifex::proxy` and `pontifex::aws_credentials`.
//!
//! Proxy success means transport completion, not KMS authorization.

use pontifex::{
    aws_credentials::CredentialsUnavailable,
    proxy::{Event, Outcome},
};
use telemetry_batteries::reexports::metrics;

/// Records one proxy event under `migration.kms_relay.*`.
pub fn record_proxy_event(event: Event) {
    match event {
        Event::Closed { outcome, duration } => {
            metrics::counter!(
                "migration.kms_relay.requests",
                "kind" => "tls",
                "outcome" => proxy_outcome(outcome)
            )
            .increment(1);
            metrics::histogram!("migration.kms_relay.duration_seconds", "kind" => "tls")
                .record(duration.as_secs_f64());
        }
        Event::RejectedPeer => {
            metrics::counter!("migration.kms_relay.rejected", "reason" => "peer").increment(1);
        }
        Event::AcceptFailed => {
            metrics::counter!("migration.kms_relay.accept_failures").increment(1);
        }
        _ => metrics::counter!("migration.kms_relay.unknown_events").increment(1),
    }
}

/// Records one credentials request under `migration.kms_relay.requests`.
pub fn record_credentials_result(result: Result<(), CredentialsUnavailable>) {
    let outcome = match result {
        Ok(()) => "success",
        Err(CredentialsUnavailable::ProviderFailed) => "provider_failed",
        Err(CredentialsUnavailable::TimedOut) => "timeout",
        Err(CredentialsUnavailable::Invalid(_)) => "invalid",
    };
    metrics::counter!(
        "migration.kms_relay.requests",
        "kind" => "credentials",
        "outcome" => outcome
    )
    .increment(1);
}

const fn proxy_outcome(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Completed => "success",
        Outcome::ConnectFailed => "connect_failed",
        Outcome::ConnectTimedOut => "connect_timeout",
        Outcome::IdleTimedOut => "idle_timeout",
        Outcome::Io => "io",
        _ => "other",
    }
}
