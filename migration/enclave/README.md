# Migration debug report

The enclave returns an encrypted JSON diagnostic for requests it can unseal. It
finalizes the report after migration processing, including output-PCP preparation,
signing and response sealing. The diagnostic is sealed separately to the request's
response key. A host receives only ciphertext.

The [JSON schema](debug-report.schema.json) defines the envelope. Its exact UTF-8
bytes are SHA-256 hashed into the report's top-level `version`. The
[example](debug-report.example.json) uses synthetic identifiers, measurements and
engine diagnostics; the enclave tests compare it with serialized output.

```text
report
├── signup_id
├── src_signup_id
├── version
├── metadata
│   ├── start_timestamp, end_timestamp
│   ├── signup_status, signup_reason
│   ├── source_pcp_version
│   ├── software_version
│   ├── environment
│   │   ├── type, boot_id
│   │   └── tee
│   │       ├── technology
│   │       └── attestation
│   └── hardware
├── face
│   ├── request_type
│   └── outputs[]
├── iris
│   ├── left
│   ├── right
│   └── pair
└── pipeline_errors
    └── migration_error
```

## Field sources

| Field | Source and meaning |
|---|---|
| `signup_id` | The same structured `SignupId` allocated in the output PCP's `MigrationContext`; null before allocation |
| `src_signup_id` | The parsed source PCP's signup ID in the same structured representation; null if unavailable or not representable |
| `metadata.start_timestamp`, `end_timestamp` | Enclave operation boundaries in Unix seconds with fractional precision; null if the clock is invalid |
| `metadata.source_pcp_version` | The parsed source format, also used for `migration.pb.source_pcp_version` |
| `metadata.software_version.main_program_version` | Enclave package version, also used for `migration.pb.tee_software_version` |
| `metadata.software_version.worker_sha384` | Verified worker executable digest from provisioning; the successful PCP uses the same identity in `migration.pb.biometric_pipeline_version` |
| `metadata.software_version.worker_version` | Worker JSON's package version, cross-checked with the face wrapper when both are present |
| `metadata.software_version.face_engine_version` | Available face analyzer/template-generator version labels, provided they agree |
| `metadata.software_version.iris_engine_version` | Available `iris.left/right.outputs.capture_qa.metadata.irnet_version`, `library_version`, and explicit worker `iris_engine_version` labels; all available labels must agree |
| `metadata.environment.type`, `tee.technology` | `tee` and `aws_nitro_enclaves` for this enclave implementation |
| `metadata.environment.boot_id` | Hex-encoded public channel-key commitment; changes on enclave restart |
| `metadata.environment.tee.attestation` | Observed NSM PCR0/1/2 and the zeroed-measurement observation from the boot attestation document |
| `metadata.hardware` | Architecture, usable logical CPUs and total enclave-visible memory observed at startup |

Unavailable optional metadata is omitted. Collection errors and inconsistent
version labels produce bounded warnings without logging report contents. Hardware
observations describe the enclave allocation. PCR values describe the NSM
observation; they do not assert that an external verifier accepted an attestation.

`face` and `iris` preserve complete worker diagnostic objects and null engine
results. The common worker package version lives in `metadata.software_version`.
Engine JSON is borrowed from zeroizing storage and serialized without conversion
through floating-point values, preserving numeric precision and additional engine
fields. An absent diagnostic branch is null; it does not imply a passing check.

## Outcome and failure contract

| Result | `signup_status` | `signup_reason` |
|---|---|---|
| Output PCP prepared and response sealed | `Success` | `Normal` |
| Biometric spoof rejection | `Fraud` | `Fraud` |
| Other terminating processing failure | `Failure` | `Failure` |

These outcomes cover enclave processing. A quality rejection is `Failure`, and
`Fraud` describes a spoof-check classification rather than a person's intent.

`pipeline_errors.migration_error` is null on success. On failure it records the
enclave phase and bounded public error code, plus a worker image role and
structured invalid-request reason when supplied. A failure after inference retains
the worker diagnostics while reporting the final failure. Detailed engine errors
remain in their engine objects.

Requests that cannot be unsealed have no report. Recoverable errors after unsealing
can return an encrypted envelope even without worker diagnostics. Malformed worker
JSON is excluded with a warning; available enclave metadata and outcome remain.
A complete report must fit the 2 MiB plaintext limit. Serialization, size-limit or
diagnostic-encryption failures are logged and omit the report while preserving the
primary migration result. Engine diagnostics are never truncated to fit. A fatal
worker/enclave exit cannot guarantee a final report.
