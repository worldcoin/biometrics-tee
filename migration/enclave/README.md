# Migration debug report

A report containing debug information about the TEE migration.

The enclave finalizes the report after PCP processing and seals it to the request’s
response key. The [schema](src/debug_report/schema.json) defines the envelope;
SHA-256 of its exact bytes supplies the top-level `version`.

- `signup_id` and `src_signup_id` identify the output and source PCPs.
- `metadata` records operation timestamps, outcome, software versions, observed
  enclave resources, TEE technology, boot identity and measurements.
- `face` and `iris` preserve complete worker diagnostics and numeric precision.
- `pipeline_errors.migration_error` records the terminating phase and error.

| Enclave outcome | `signup_status` | `signup_reason` |
|---|---|---|
| PCP prepared and sealed | `Success` | `Normal` |
| Spoof rejection | `Fraud` | `Fraud` |
| Other processing failure | `Failure` | `Failure` |

Unavailable optional metadata is omitted; null engine outputs do not imply success.
Report serialization stops at the 2 MiB plaintext limit. Serialization and encryption
errors or unwinding panics omit the report while preserving the migration result;
engine output is never truncated. Optional boot metadata collection is also isolated.

The host stores the PCP and records the primary outcome before uploading the report.
Report uploads are bounded to five seconds; invalid sizes, storage errors, timeouts
and upload-task panics are logged and counted by `migration.host.debug_report_failures`.
The API discovers reports independently in storage, so a subsequent status poll may
include a report URL after the migration is already complete.
Unsealing failures have no report. Process-wide failures such as allocation aborts,
stack overflow and termination cannot be recovered by panic isolation.
