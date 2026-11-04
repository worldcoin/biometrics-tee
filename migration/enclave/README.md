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
- `pipeline_errors.migration_error` records `stage`, `code`, `component` and
  `invalid_request_reason`. The component is `Face`, `LeftIris`, `RightIris`,
  `IrisPair`, or null when unavailable. Detailed engine errors remain in `face`
  and `iris`.
- `pipeline_errors.worker_failure` preserves the worker's complete failure
  summary, including detailed quality, spoof and internal reason codes. It is
  null when the worker omits it, returns null or supplies a non-object value.
  Engine execution-error messages remain in the complete `iris` diagnostics.

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

`iris_code_comparison` compares the source PCP's iris templates with the worker's
regenerated templates, separately for each eye. It is null until a worker succeeds.
Each eye records `zero_shift` and `rotation_adjusted`, with the masked Hamming
distance, differing-bit count, common-valid-bit count and rotation in columns.
Each eye also records the old and new masks’ valid-bit counts.
The distance is differing code bits divided by common valid bits; a bit counts
only when both masks mark it valid. The regenerated template and mask are the
probe, rolled along columns within each row against the source gallery.
The rotation search visits 0, -1, +1, ..., -15, +15 and retains the first minimum.

The supported worker code version is `v2.1`: 16 rows, 200 columns, two filters and
two phase bits, packed MSB-first into 1,600 bytes. All four decoded buffers must
have that size. Source `IRIS_version` is pipeline provenance, not a code-format
identifier, and is recorded separately from `worker_iris_code_version`.
`worker_iris_version` uses the same agreed worker diagnostic version as
`metadata.software_version.iris_engine_version`; it is null when the version is
unavailable, malformed or inconsistent.
Additional template formats require an explicit layout and compatibility check.
A distance with no common valid bits is null; an eye with no valid rotation has
status `no_valid_overlap`. Missing data, unsupported versions and invalid
encodings/lengths have explicit statuses. These diagnostics do not gate migration.
Only summary measurements enter the encrypted report; template buffers are
zeroized after comparison and never included in the report or application logs.
