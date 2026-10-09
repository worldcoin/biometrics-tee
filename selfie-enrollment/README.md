# Selfie Check enrollment: embedding extraction

This application follows Flamingo's public host / measured enclave / private sandboxed worker split. It exposes one operation: extract an embedding from a VanillaSelfie image. It does not issue credentials, construct a PCP or implement interactive biometric challenges.

## Protocol

`GET /v1/embeddings` upgrades to a WebSocket. The host sends an admission nonce, the caller obtains a P256 ticket from its trusted test issuer, and the host verifies the ticket before accessing the enclave. Tickets expire within 60 seconds and commit to the audience and the connection's random nonce, so a captured ticket cannot authorize another socket. Native clients may omit Origin; browser Origins must be explicitly allowed. The issuer's signing key never belongs in browser code.

The enclave returns its boot-scoped channel key, Nitro attestation and a single-use 60-second assignment nonce. The client verifies the AWS chain, document freshness, PCR0/1/2, channel-key commitment and worker identity before sealing an image. A release allowlist entry binds all three measurements to a specific worker executable SHA-384. There is no measurement-bypass option.

The attestation's `user_data` contains CBOR `WorkerIdentity`: the enclave-verified executable digest plus `selfie-enrollment/vanilla-selfie/v1`. The digest is immutable for the boot and covers the worker's embedded models. It differs from the archive SHA-256 verified by the host provisioner. Model/worker releases can change independently of the public broker EIF while remaining subject to the client's explicit allowlist.

The sealed CBOR request contains protocol version 1, the assignment nonce and an image of at most 8 MiB. The enclave consumes the nonce and permits one worker operation at a time. A response carries either a typed image/quality failure or the original worker vector encoding, type, version, inference backend and worker identity. Responses are padded to 64 KiB before sealing. No image, embedding or worker debug report is logged or persisted by the host. Biometric plaintext types erase their owned buffers on drop.

## Layout and dependencies

- `api-types`: public session/admission messages and limits.
- `enclave-types`: ciphertext-only Pontifex RPCs and health.
- `sealed-types`: client/enclave plaintext types and strict codecs.
- `enclave`: worker bootstrap, Minijail adapter, attested keys, assignment replay protection and extraction policy.
- `host`: admission, bounded WebSocket relay, health/readiness and graceful shutdown.
- `e2e`: native diagnostic command and loopback-only browser harness/test issuer.
- `client`: shared verification and sealing, native transport, browser WASM transport with bounded incoming queue and AbortSignal support.

The shared `sandbox/` crate remains byte-oriented. Its bundle receiver uses the pinned Flamingo consolidation from #60; this branch includes that foundation. Enrollment uses the published `biometric-engines-protocol` face contract rather than DI's vendored migration protocol. The worker is started before broker keys or executor threads exist. Worker transport/protocol failures terminate the enclave; image/quality rejections remain recoverable.

## Build and validation

```sh
cargo test --locked -p selfie-enrollment-api-types -p selfie-enrollment-sealed-types \
  -p selfie-enrollment-enclave -p selfie-enrollment-host -p selfie-enrollment-client
cargo check --locked -p selfie-enrollment-client --target wasm32-unknown-unknown
scripts/build-enclaves.sh --workload selfie-enrollment target/eif
```

The enclave build needs x86_64 Linux/Nix. Linux runtime and Minijail checks run in CI; a Mac test run cannot qualify them. Boot rejects Nitro debug mode. The host requires `ADMISSION_PUBLIC_KEY` (SEC1 P256 hex) and `ADMISSION_AUDIENCE`; browser clients additionally need `ALLOWED_ORIGINS`. Host defaults are port 8000, enclave CID 16/port 1000 and eight concurrent sockets.

The browser export is `extractEmbedding(configJson, imageBytes, issueTicket, abortSignal)`. `issueTicket(challenge)` returns a promise resolving to `{ expires_at, signature }`; its signature is fixed-width P256 hex over `api_types::ticket_message`. Configuration provides the exact `wss://.../v1/embeddings` endpoint, audience, and `releases: [{ pcr0, pcr1, pcr2, worker_sha384 }]`, with lowercase hex SHA-384 measurements. Local loopback `ws://` is permitted for protocol tests, with the same mandatory attestation checks.

## Deployment

`worldcoin/tee-apps` owns paired host/EIF publication and Argo values. Staging uses the independent `selfie-enrollment-v1` node track and the `selfie-enrollment` namespace/service account. Required infrastructure is tracked in worldcoin/infrastructure#50677. Initial acceptance must use trusted build measurements and a pinned real worker on non-debug Nitro; local fake-worker tests do not establish a deployed extraction service or camera liveness.

## Exercise a measured staging release

Use the reviewed `client-stage.json` from tee-apps; never construct the allowlist from an untrusted host's response. On an operator machine:

```sh
cargo run --locked -p selfie-enrollment-e2e -- keygen --directory /private/tmp/enrollment-issuer
cargo run --locked -p selfie-enrollment-e2e -- extract \
  --config /path/to/client-stage.json --image /path/to/approved-test-image.jpg \
  --admission-key /private/tmp/enrollment-issuer/admission-private.hex
```

Configure only `admission-public.hex` on the staging host. Private keys and explicit `--output` files are created with mode 0600 and never overwritten. The default diagnostic output includes only embedding metadata and worker identity. The local issuer is a test facility, not a credential-issuance authorization method.

For the browser harness, install matching wasm-bindgen CLI 0.2.126 and build:

```sh
cargo build --locked -p selfie-enrollment-client --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir target/enrollment-web \
  target/wasm32-unknown-unknown/debug/selfie_enrollment_client.wasm
cargo run --locked -p selfie-enrollment-e2e -- serve \
  --config /path/to/client-stage.json \
  --admission-key /private/tmp/enrollment-issuer/admission-private.hex
```

Open `http://127.0.0.1:8765` and select the approved image. The harness sends the encrypted image directly to the TEE host and only the public admission challenge to its local issuer. The issuer rejects non-loopback Host headers, missing/cross-origin Origin headers and a wrong audience. No private key or biometric payload is served by the issuer. Cancel aborts the entire exchange, including a pending issuer promise.

WASM linking requires a WASM-capable C compiler and LLVM archiver for the attestation verifier's `ring` dependency. On macOS, set `CC_wasm32_unknown_unknown` and `AR_wasm32_unknown_unknown` to LLVM tools; the Apple archiver cannot index WASM objects. CI links the WASM and runs twelve Chromium/WebKit regressions for untrusted attestation, stalled-issuer cancellation, pre-aborted requests, oversized messages, flooding and invalid policy. These are adversarial transport tests with mocked WebSocket events, not live Nitro extraction.
