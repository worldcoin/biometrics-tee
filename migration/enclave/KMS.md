# PCP recipient wrapping

`BackendKeys::generate` creates four fresh sealed-box keypairs inside the
enclave. KMS Encrypt receives each raw 32-byte private key over enclave-terminated
TLS. `di_migration_pcp::build` accepts `OutputRecipients` containing the public keys
and standard Base64 KMS ciphertexts, and delegates to the shared PCP builder. The
builder encrypts the inner archives, writes `backend_keys.json`, hashes it in the
manifest, and calls the supplied
manifest signer. The caller supplies the authenticated source, prepared biometrics,
authorized user public key and signing callback. Package construction is synchronous
and belongs on a blocking worker after asynchronous key generation. Run
`di_migration_pcp::validate_build_inputs` before generating keys to reject invalid
mapping inputs and unusable user keys without KMS calls. Retain the source through
the completed-package preservation check.

The enclave state exposes the configured `KeyWrapper` for this integration. The
migration route verifies the credential and PCP hash before a channel round trip.
Source processing and signer integration must call the package construction
component before it can produce migrated PCPs.

## Configuration and trust

The image embeds the wrapping key or alias ARN and its derived region in its
measured environment. The enclave requires a full KMS key or alias ARN in the
configured region at startup. Terraform owns deployment policy. Cross-account
aliases include the key owner's account ID, for example this **synthetic** value:

```sh
scripts/build-enclaves.sh --workload migration \
  --pcp-kms-key-arn arn:aws:kms:us-east-1:000000000000:alias/example
```

Store real environment values in deployment configuration. The bare name
`alias/example` resolves in the caller's account. AWS KMS resolves the configured
alias when processing the encryption request. Alias changes require preserving
decrypt access to keys referenced by existing ciphertexts.

Set `PCP_KMS_REGION` on the host to the alias's region. The host uses its existing
AWS SDK credential provider, which must supply temporary credentials with a session
token and at least 60 seconds of remaining validity. Both its IAM policy and the
key-owning account's KMS policy must allow `kms:Encrypt` on the target key. No
`kms:Decrypt` permission is needed by this producer.

The host binds parent CID 3, ports 7000 (TLS relay) and 7001 (credentials). It checks
the connecting CID against `ENCLAVE_CID`, limits active connections to 32 and only
forwards to the configured regional AWS KMS hostname on port 443. These ports must
be available in the host's vsock namespace. The enclave validates TLS using its
compiled public trust roots and the hostname derived from the measured region. Host
credentials authorize requests; they do not choose the wrapping destination.

Each credential exchange has a three-second deadline. The enclave SDK caches
credentials and refreshes them before expiration. Each TLS/HTTP exchange has a
five-second deadline and a 64 KiB response limit. `KeyWrapper::encrypt` allows at
most two four-second attempts within a ten-second operation deadline. Four private
keys are encrypted sequentially, with a combined wrapping deadline of at most
40 seconds, plus local key generation.
Failure discards the partial recipient bundle and returns no package.

Key generation uses libsodium guarded memory. Each raw private key is copied into
`Zeroizing<Vec<u8>>`, whose ownership is preserved by the SDK's `Blob` through
`Bytes::from_owner` and `Blob::from_maybe_shared`. The raw-key allocation is wiped
when its last owner is dropped. KMS Encrypt uses the SDK's standard serialization,
signing and retry path. SDK-generated JSON and transport buffers follow normal
SDK memory management and are not zeroized. Keep AWS SDK debug/trace body logging
disabled.

The enclave completes the TLS handshake before sending HTTP requests. The HTTP
connection is scoped to the request future, so request deadlines also close it.

The image build selects the enclave package explicitly. Its production KMS SDK
dependency enables the Tokio runtime and uses the supplied TLS connector. The
SDK's default HTTPS client is enabled only for tests that use LocalStack.

## Deployment and checks

Deploy the host relay before enabling package generation. Build the enclave with
the environment's alias ARN and register the resulting measurements through the
normal attestation rollout. An image without wrapping configuration has no
`KeyWrapper`; callers must reject package generation in that mode. Liveness does
not depend on AWS KMS availability.

Run the portable regression suite and the synthetic KMS integration test:

```sh
cargo test --locked -p di-migration-enclave-primitives -p di-migration-enclave -p di-migration-host
LOCALSTACK_ENDPOINT=http://localhost:4566 cargo test --locked \
  -p di-migration-enclave --test pcp_keys -- --ignored
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
The enclave emits wrapping failures with archive role and a payload-free error
class. Upstream messages and response bodies are excluded. Connecting enclave
outcomes to production job metrics and alerting belongs to the migration-route
integration; relay metrics alone cannot measure successful package generation.
