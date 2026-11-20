# Migration startup configuration

Build the migration EIF once with `scripts/build-enclaves.sh --workload migration`.
The same image can run in stage and production: environment-specific keys are supplied by the
launcher at startup through `ENCLAVE_APPLICATION_CONFIG`.

```json
{
  "PCP_KMS_KEY_ARN": "arn:aws:kms:eu-central-1:000000000000:key/12345678-1234-1234-1234-123456789012",
  "PCP_KMS_SIGNING_KEY_ARN": "arn:aws:kms:eu-central-1:000000000000:key/87654321-4321-4321-4321-210987654321",
  "ISSUER_PUBKEY_X": "<decimal BabyJubJub X coordinate>",
  "ISSUER_PUBKEY_Y": "<decimal BabyJubJub Y coordinate>"
}
```

The launcher transfers this JSON with the worker bundle. The enclave requires exactly these four
fields and validates them before launching the worker or acknowledging readiness. Both KMS values
must be concrete `key/` ARNs (including multi-region `mrk-` IDs); mutable aliases are rejected.
The issuer must be a nonidentity BabyJubJub subgroup point with canonical decimal coordinates.
Configuration stays fixed for the life of that boot. Changing it requires a restart, without a rebuild.

These are trusted deployment choices outside the EIF measurements. TFH operates deployment
configuration; PCR approval identifies the enclave build and does not authorize these runtime values.
The launcher forwards only this payload, and it is not passed to the biometric worker.

## KMS access

- Use the concrete key behind `alias/self_custody` for `PCP_KMS_KEY_ARN`. The same configured key
  decrypts source PCP backend-key envelopes and wraps newly generated backend keys. A different
  key cannot decrypt a genuine source envelope created with the intended key.
- `PCP_KMS_SIGNING_KEY_ARN` selects the RSA key used with `RSASSA_PSS_SHA_256` to sign the output
  manifest. Startup resolves its metadata with `kms:DescribeKey`. `migration.pb` records the bare
  key ID as `signing_key_id`; consumers use it as `tee_key_id` when obtaining the trusted public key
  from authentication-service. Previously generated packages may contain an ARN in this field.
- KMS key material stays in KMS. The host supplies temporary AWS credentials and relays TLS;
  TLS terminates inside the enclave. IAM and the key owner's policy must allow `kms:Encrypt` and
  `kms:Decrypt` on the wrapping key, and `kms:Sign` plus `kms:DescribeKey` on the signing key.
- The host's `AWS_REGION` must match both key ARNs. Its vsock ports 7000 (KMS relay) and 7001
  (temporary credentials) must be available.

## Rollout

1. Pin matching Tabernaculum Rust and provisioner-image versions supporting bootstrap manifest v5.
2. Deploy the migration image with all four runtime settings. Missing or invalid configuration,
   or a failed signing-key lookup, prevents readiness.
3. On Nitro hardware, verify source-key decryption, output key wrapping and manifest signing through
   the existing migration flow. Local tests do not establish vsock connectivity or IAM access.
4. For rollback, restore the previous matching image and deployment configuration. Preserve keys
   referenced by existing packages.

Monitor `migration.kms_relay.requests` (by `kind`, `outcome`), `.duration_seconds`,
`.rejected` (by `reason`) and `.accept_failures`. Their success means transport completion,
not KMS authorization.
