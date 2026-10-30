# Migration debug report

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
Reports must fit the 2 MiB plaintext limit. Diagnostic failures are logged and omit
the report while preserving the migration result; engine output is never truncated.
Unsealing failures have no report; a fatal process exit may prevent one.
