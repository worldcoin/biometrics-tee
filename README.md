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

Debug-report upload failures preserve the primary migration outcome. They emit
`migration.host.debug_report_failures{reason:storage}` and a warning with the job
ID and storage error; the report contents are never logged.

Report lookup or signing failures also preserve the known migration status and
any PCP download URL. The response omits the report URL and expiry, logs a warning,
and increments `migration.api.debug_report_failures{reason:storage}`.

Migration clients seal the recipient `device_public_key` with the PCP and credential
in payload version 2. The key is absent from the init request and job metadata;
only the enclave reads it, for PCP tier encryption. Upgrade the API, hosts,
enclaves, and clients together: legacy payloads without a bound key are rejected.

The enclave seals the PCP response and debug report separately to the same
request-bound Pontifex response key. Export `MigrationResponseOpener::into_secret_bytes()` before
unsealing either artifact and pass the saved secret to the Rust client's
`fetch_pcp` and `fetch_debug_report`; both remove the
Pontifex response envelope and return its plaintext bytes. Response secrets and
unsealed payloads use `Zeroizing<Vec<u8>>` buffers that are wiped on drop. Clone the
saved secret when downloading both artifacts, and keep it private.

Debug reports may contain up to 2 MiB (2,097,152 bytes) of plaintext JSON. The
sealed size limit includes Pontifex overhead. The worker response budget is 3 MiB
to accommodate the report alongside the biometric result.

Roll out matching host, enclave, and client versions: the report sealing format
and accepted size bounds changed. Previously stored reports still use device-key
encryption and cannot be opened with the response key.

## Sandboxed workers

The dev and Selfie Check enclaves run their workers through [tabernaculum](https://github.com/worldcoin/tabernaculum), pinned by git revision.
It receives the worker bundle, stages the executable at `bin/worker` and runs it under Minijail with its default seccomp policy.
Each enclave owns its worker protocol; tabernaculum's CI runs the bundle, transport and Minijail process tests.

## Selfie Check enrollment

See [selfie-enrollment](selfie-enrollment/README.md) for the separate embedding-extraction application, attestation contract, native/browser client and staging deployment boundary.
