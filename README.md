## Deep Identifier Migration

WIP

The host emits `migration.host.job_failures`, tagged with the public `reason` value.
It counts each failed attempt observed by the runner, including jobs skipped after
their queue deadline, even if recording the outcome in DynamoDB fails. It is not
an authoritative count of persisted job statuses or API-side timeouts.

Datadog tracing (`TELEMETRY_PRESET=datadog`) does not enable metrics. Configure the
host to send DogStatsD metrics to the node's Datadog agent:

```yaml
TELEMETRY_METRICS_BACKEND: statsd
TELEMETRY_STATSD_HOST: "$(DATADOG_AGENT_HOST)"
TELEMETRY_STATSD_PORT: "8125"
```

`DATADOG_AGENT_HOST` must be defined earlier in the pod's environment from
`status.hostIP`. The agent must accept UDP traffic from pods on port 8125.
These settings also enable the existing `migration.kms_relay.*` metrics.
The host and API disable the exporter's UDP buffering so low-volume metrics are
sent immediately; the exporter has no periodic flush.
In Datadog, counts per reason can be queried with
`sum:migration.host.job_failures{*} by {reason}.as_count()`.

## Sandboxed workers

The dev and Selfie Check enclaves run their workers through [tabernaculum](https://github.com/worldcoin/tabernaculum), pinned by git revision.
It receives the worker bundle, stages the executable at `bin/worker` and runs it under Minijail with its default seccomp policy.
Each enclave owns its worker protocol; tabernaculum's CI runs the bundle, transport and Minijail process tests.

## Selfie Check enrollment

See [selfie-enrollment](selfie-enrollment/README.md) for the separate embedding-extraction application, attestation contract, native/browser client and staging deployment boundary.
