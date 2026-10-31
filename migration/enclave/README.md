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
- `pipeline_errors.migration_error` records the terminating TEE `stage` and `code`,
  the failing `component`, and the exact `pipeline_code` / `pipeline_message` when
  available. `invalid_request_reason` retains input-validation details.

For a left-eye capture QA rejection, the summary contains:

```json
{
  "stage": "biometrics",
  "code": "BiometricQualityRejected",
  "component": "iris.left.capture_qa",
  "pipeline_code": "IrisUnsharp",
  "pipeline_message": "iris texture is unsharp",
  "invalid_request_reason": null
}
```

The summary reads explicit stage-level errors only in the worker-reported failing
branch. Iris capture QA, iris processing, PAD, face analysis/template generation
and pair checks have known diagnostic layouts. Later-stage output after a terminal
error is ambiguous. Missing, malformed or ambiguous details retain the broad
component (`face`, `iris.left`, `iris.right`, `iris.pair`) with null pipeline fields.
Non-biometric failures have null component/pipeline fields. Pair checks expose the
check name; messages are copied only when the engine supplies them. Full engine
outputs retain their original structure and precision. Summary details never alter
the migration outcome and are returned only in the encrypted report.

`metadata.environment.tee.attestation.measurements_zeroed` is true when PCR0,
PCR1 and PCR2 are all present as 48-byte zero digests. These image measurements
are zeroed in debug mode; parent-instance PCRs can remain nonzero. A false value
does not establish verified code identity or replace attestation verification.

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
