# Migration debug report

A report containing debug information about the TEE migration.

The enclave finalizes the report after PCP processing and seals it to the request’s
response key. The [schema](src/debug_report/schema.json) defines the envelope;
SHA-256 of its exact bytes supplies the top-level `version`.

- `signup_id` is allocated once after request unsealing, before payload decoding,
  credential checks or biometric processing. It identifies the migration attempt
  on failure and is reused as the output PCP ID on success. It does not imply
  that a PCP was produced.
- `src_signup_id` identifies the validated source PCP. It is null until the source
  is parsed, or when its ID cannot be represented as a structured signup ID.
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
