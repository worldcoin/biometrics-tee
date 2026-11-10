//! Migration service telemetry with Datadog tags on custom metrics.

use std::env;

use anyhow::Context;
use metrics_exporter_statsd::{StatsdBuilder, StatsdRecorder};
use telemetry_batteries::{MetricsBackend, StatsdConfig, TelemetryConfig, TelemetryGuard};

/// Initializes telemetry, retaining the returned guard until the service stops.
///
/// # Errors
///
/// Returns an error for invalid configuration or if tracing or metrics initialization fails.
pub fn init() -> anyhow::Result<TelemetryGuard> {
    let mut config = TelemetryConfig::from_env()
        .map_err(|error| anyhow::anyhow!("failed to load telemetry configuration: {error:?}"))?;
    let recorder = if matches!(config.metrics.backend, MetricsBackend::Statsd) {
        let service = config
            .service_name
            .as_deref()
            .context("TELEMETRY_SERVICE_NAME is required for StatsD metrics")?;
        let environment = optional_env("DD_ENV")?;
        let version = optional_env("DD_VERSION")?;
        let recorder = statsd_recorder(
            &config.metrics.statsd,
            service,
            environment.as_deref(),
            version.as_deref(),
        )?;
        // telemetry-batteries 0.4.1 does not add service tags to its StatsD recorder.
        config.metrics.backend = MetricsBackend::None;
        Some(recorder)
    } else {
        None
    };

    let guard = telemetry_batteries::init_with_config(config)
        .map_err(|error| anyhow::anyhow!("failed to initialize telemetry: {error:?}"))?;
    if let Some(recorder) = recorder {
        telemetry_batteries::reexports::metrics::set_global_recorder(recorder)
            .context("failed to install tagged StatsD recorder")?;
    }
    Ok(guard)
}

fn optional_env(name: &str) -> anyhow::Result<Option<String>> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => anyhow::bail!("{name} must contain valid UTF-8"),
    }
}

fn statsd_recorder(
    config: &StatsdConfig,
    service: &str,
    environment: Option<&str>,
    version: Option<&str>,
) -> anyhow::Result<StatsdRecorder> {
    let mut builder = StatsdBuilder::from(&config.host, config.port)
        .with_queue_size(config.queue_size)
        // The exporter has no timed flush; sparse job events must be sent immediately.
        .with_buffer_size(0)
        .with_default_tag("service", service);
    if let Some(environment) = environment {
        builder = builder.with_default_tag("env", environment);
    }
    if let Some(version) = version {
        builder = builder.with_default_tag("version", version);
    }
    builder
        .build(config.prefix.as_deref())
        .context("failed to build tagged StatsD recorder")
}

#[cfg(test)]
mod tests {
    use std::{net::UdpSocket, time::Duration};

    use telemetry_batteries::reexports::metrics;

    use super::*;

    #[test]
    fn sparse_metrics_include_service_and_deployment_tags() {
        for service in ["di-migration-host", "di-migration-api"] {
            let packet = record_metric(service, Some("stage"), Some("sha-test"));
            let (metric, tags) = packet.split_once("|#").expect("metric must have tags");
            assert_eq!(metric, "test.migration.kms_relay.requests:1|c");
            let mut tags: Vec<_> = tags.split(',').collect();
            tags.sort_unstable();
            assert_eq!(
                tags,
                [
                    "env:stage",
                    "kind:tls",
                    &format!("service:{service}"),
                    "version:sha-test"
                ]
            );
        }
    }

    #[test]
    fn local_metrics_do_not_require_deployment_tags() {
        let packet = record_metric("di-migration-host", None, None);
        assert!(packet.contains("service:di-migration-host"));
        assert!(!packet.contains("env:"));
        assert!(!packet.contains("version:"));
    }

    fn record_metric(service: &str, environment: Option<&str>, version: Option<&str>) -> String {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let config = StatsdConfig {
            host: "127.0.0.1".to_owned(),
            port: receiver.local_addr().unwrap().port(),
            prefix: Some("test".to_owned()),
            ..StatsdConfig::default()
        };
        let recorder = statsd_recorder(&config, service, environment, version).unwrap();
        metrics::with_local_recorder(&recorder, || {
            metrics::counter!("migration.kms_relay.requests", "kind" => "tls").increment(1);
        });
        let mut packet = [0; 1024];
        let length = receiver
            .recv(&mut packet)
            .expect("a single metric must flush immediately");
        String::from_utf8(packet[..length].to_vec()).unwrap()
    }
}
