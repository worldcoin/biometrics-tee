# PCP recipient wrapping

`WrappedPcpKeys::generate` creates four fresh sealed-box keypairs inside the
enclave. KMS Encrypt receives each raw 32-byte private key over enclave-terminated
TLS. `pcp_keys::build` passes the corresponding public keys and standard Base64
KMS ciphertexts to the shared PCP builder. The builder encrypts the inner archives,
writes `backend_keys.json`, hashes it in the manifest, and calls the supplied
manifest signer. The caller supplies the authenticated source, prepared biometrics,
authorized user public key and signing callback. Package construction is synchronous
and belongs on a blocking worker after asynchronous key generation.

The enclave state exposes the configured `KeyWrapper` for this integration. The
migration route currently performs a channel round trip; source processing and
signer integration must call the package construction component before it can
produce migrated PCPs.

## Configuration and trust

The full wrapping key or alias ARN is baked into the image environment and covered
by its measurements. Cross-account calls require an alias ARN containing the key
owner's account ID, for example this **synthetic** value:

```sh
scripts/build-enclaves.sh --workload migration \
  --pcp-kms-key-arn arn:aws:kms:us-east-1:000000000000:alias/example
```

Store real environment values in deployment configuration. The bare name
`alias/example` resolves in the caller's account and is rejected. AWS resolves
the configured alias; its Encrypt response must name a concrete key in the same
partition, account and region. Alias changes require preserving decrypt access to
keys referenced by existing ciphertexts.

Set `PCP_KMS_REGION` on the host to the alias's region. The host uses its existing
AWS SDK credential provider, which must supply temporary credentials with a session
token and at least 60 seconds of remaining validity. Both its IAM policy and the
key-owning account's KMS policy must allow `kms:Encrypt` on the target key. No
`kms:Decrypt` permission is needed by this producer.

The host binds parent CID 3, ports 7000 (TLS relay) and 7001 (credentials). It checks
the connecting CID against `ENCLAVE_CID`, limits active connections to 32 and only
forwards to the configured regional AWS KMS hostname on port 443. These ports must
be available in the host's vsock namespace. The enclave validates TLS using its
compiled public trust roots and the hostname derived from the measured ARN. Host
credentials authorize requests; they do not choose the wrapping destination.

Each credential exchange has a three-second deadline. The enclave SDK caches
credentials and refreshes them before expiration. Each TLS/HTTP exchange has a
five-second deadline and a 64 KiB response limit. Wrapping has an overall
ten-second deadline and at most two attempts; four wrappers run sequentially.
Failure discards the partial recipient bundle and returns no package. Private
keys are dropped from guarded memory after wrapping; transient SDK copies must
never be captured by body logging. Keep AWS SDK debug/trace body logging disabled.

## Deployment and checks

Deploy the host relay before enabling package generation. Build the enclave with
the environment's alias ARN and register the resulting measurements through the
normal attestation rollout. A malformed ARN fails enclave startup. An image
without wrapping configuration has no `KeyWrapper`; callers must reject package
generation in that mode. Liveness does not depend on AWS KMS availability.

Run the portable regression suite and the synthetic KMS integration test:

```sh
cargo test --locked -p di-migration-enclave-primitives -p di-migration-enclave -p di-migration-host
LOCALSTACK_ENDPOINT=http://localhost:4566 cargo test --locked \
  -p di-migration-enclave --test pcp_keys localstack_ -- --ignored
```

Before enabling production jobs, verify on Nitro hardware that the workload's
temporary credentials can wrap four synthetic keys through the regional alias.
Use a separately authorized test consumer to decrypt those ciphertexts and open
the synthetic archives. Local tests exercise TLS, framing, the KMS API and package
compatibility; they do not establish deployed vsock connectivity or IAM access.
Roll back to the prior approved enclave image and measurements if the smoke check
fails, and keep the wrapping KMS keys available for already produced packages.

The host's existing telemetry initialization supports StatsD when
`TELEMETRY_METRICS_BACKEND=statsd` is configured. Monitor
`migration.kms_relay.requests` by `kind` and `outcome`,
`migration.kms_relay.duration_seconds`, and `migration.kms_relay.rejected` by
`reason`. Relay success describes transport completion, not KMS authorization.
The enclave emits payload-free wrapping failures with archive role and error
class. Connecting enclave outcomes to production job metrics and alerting belongs
to the migration-route integration; relay metrics alone cannot measure successful
package generation.
