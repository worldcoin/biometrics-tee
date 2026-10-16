# PCP key wrapping: configuration and rollout

## Configuration

- Build the migration EIF with the full wrapping key ARN; it is part of the measured image:

  ```sh
  scripts/build-enclaves.sh --workload migration \
    --pcp-kms-key-arn arn:aws:kms:us-east-1:000000000000:alias/example  # synthetic
  ```

- Use the key behind `alias/self_custody`: consumers decrypt with that `KeyId`, so a blob under
  any other key cannot be opened. Keep real values in deployment configuration.
- The host's AWS region (`AWS_REGION` or the SDK chain) must match the ARN's region.
- The host's credential provider must return temporary credentials. Its IAM policy and the
  key owner's key policy must allow `kms:Encrypt` on the key; `kms:Decrypt` is not needed.
- The host listens on vsock ports 7000 (KMS proxy) and 7001 (credentials); both must be free.

## Rollout

1. Deploy the host before enabling package generation.
2. Build the EIF with the environment's ARN and register its measurements through the normal
   attestation rollout. An image without an ARN has no `KeyWrapper`; callers must reject
   package generation then.
3. On Nitro hardware, wrap four synthetic keys and open them with a separately authorized
   consumer. Local tests do not cover vsock connectivity or IAM access.
4. If that check fails, roll back to the previous image and measurements. Never delete a
   wrapping key that existing packages reference.

Monitor `migration.kms_relay.requests` (by `kind`, `outcome`), `.duration_seconds`,
`.rejected` (by `reason`) and `.accept_failures`. Their success means transport completion,
not KMS authorization.
