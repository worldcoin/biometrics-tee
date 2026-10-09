# Selfie Check enrollment: embedding extraction

This application follows Flamingo's public host / measured enclave / private sandboxed worker split. It exposes one operation: extract an embedding from a VanillaSelfie image. It does not issue credentials, construct a PCP or implement interactive biometric challenges.

## Protocol

`GET /v1/embeddings` upgrades to a WebSocket. The host sends an admission nonce, the caller obtains a P256 ticket from its trusted test issuer, and the host verifies the ticket before accessing the enclave. Tickets expire within 60 seconds and commit to the audience and the connection's random nonce, so a captured ticket cannot authorize another socket. Native clients may omit Origin; browser Origins must be explicitly allowed. The issuer's signing key never belongs in browser code.

The enclave returns its boot-scoped channel key and Nitro attestation, following Flamingo's stateless assignment flow. The client verifies the AWS chain, document freshness, PCR0/1/2, channel-key commitment and worker identity before sealing an image. A release allowlist entry binds all three measurements to a specific worker executable SHA-384. There is no measurement-bypass option.

The attestation's `user_data` contains CBOR `WorkerIdentity`: the enclave-verified executable digest plus `selfie-enrollment/vanilla-selfie/v1`. The digest is immutable for the boot and covers the worker's embedded models. It differs from the archive SHA-256 verified by the host provisioner. Model/worker releases can change independently of the public broker EIF while remaining subject to the client's explicit allowlist.

The sealed CBOR request contains protocol version 1 and an image of at most 8 MiB. The enclave permits one worker operation at a time. Assignments reserve no state and have no per-request expiry; replaying valid ciphertext during the same enclave boot can repeat inference. A restart changes the channel key, so old ciphertext returns `reassign_required`. A response carries either a typed image/quality failure or the original worker vector encoding, type, version, inference backend and worker identity. Responses are padded to 64 KiB before sealing. Response encryption is not an independently attested or signed extraction statement; credential-issuance verification is outside this protocol. No image, embedding or worker debug report is logged or persisted by the host. Biometric plaintext types erase their owned buffers on drop.

## Layout and dependencies

- `api-types`: public session/admission messages and limits.
- `enclave-types`: ciphertext-only Pontifex RPCs and health.
- `sealed-types`: client/enclave plaintext types and strict codecs.
- `enclave`: worker bootstrap, Minijail adapter, attested keys, extraction policy.
- `host`: admission, bounded WebSocket relay, health/readiness and graceful shutdown.
- `e2e`: native diagnostic command and loopback-only browser harness/test issuer.
- `client`: shared verification and sealing, native transport, browser WASM transport with bounded incoming queue and AbortSignal support.

The shared `sandbox/` crate remains byte-oriented. Its bundle receiver uses `flamingo-verifier-sandbox-bundle` from [Flamingo server/v0.1.0-rc.2](https://github.com/worldcoin/flamingo/releases/tag/server/v0.1.0-rc.2), pinned to the release tag and locked commit. The bundle crate is not published to crates.io. Enrollment uses the published `biometric-engines-protocol` face contract rather than DI's vendored migration protocol. The worker is started before broker keys or executor threads exist. Worker transport/protocol failures terminate the enclave; image/quality rejections remain recoverable.

## Review against Flamingo

Comparison baseline: [Flamingo `48205c5`](https://github.com/worldcoin/flamingo/tree/48205c5fce4524b9f4f3cad079eb5813f3cce0ab). These are the enrollment-specific decisions to review:

| Difference | Enrollment behavior | Review here |
| --- | --- | --- |
| Operation and result | One `VanillaSelfie` image becomes an embedding and metadata. No comparison threshold, PCP validation, match-token signing, or signing-key attestation. Worker debug reports are erased instead of returned. | [sealed payloads](sealed-types/src/lib.rs), [worker adapter](enclave/src/engine.rs) |
| Browser admission and wire messages | `/v1/embeddings` starts with a host-issued challenge and P256 ticket; the host pushes the assignment after ticket verification. Flamingo's host waits for `assignment_request` on `/v1/matches`. Enrollment uses `{type,data}` control messages, exact browser Origin checks, and host-side test admission. | [public messages](api-types/src/lib.rs), [host session](host/src/lib.rs), [session tests](host/tests/session.rs) |
| Worker allowlist | Nitro `user_data` carries the verified worker executable digest and extraction profile. The client requires the worker digest and PCR0/1/2 to match one approved release entry. Flamingo's current `NsmAttestor` leaves `user_data` empty. | [attestation](enclave/src/attestation.rs), [startup](enclave/src/runtime.rs), [client verification](client/src/lib.rs) |
| Browser client | Native and WASM transports share verification and session sequencing. The browser transport bounds queued frames and supports cancellation; the issuer callback receives only the public admission challenge. | [shared client](client/src/lib.rs), [browser transport](client/src/browser.rs), [native transport](client/src/native.rs) |
| Limits and scheduling | One inference per enclave with immediate `busy` while occupied; Flamingo waits up to five seconds for its worker lock. Enrollment has an 8 MiB image limit, fixed 64 KiB padded results, eight default host sockets and a 90-second host session deadline. | [enclave state](enclave/src/lib.rs), [limits](api-types/src/lib.rs), [host lifecycle](host/src/lib.rs) |
| Sandbox integration | DI's existing byte-oriented Minijail process/transport remains. The PR replaces duplicated bundle provisioning with a pinned `flamingo-verifier-sandbox-bundle` dependency; enrollment supplies the typed embedding adapter. This shared dependency change also affects DI. | [sandbox re-exports](../sandbox/src/lib.rs), [workspace dependencies](../Cargo.toml), [worker adapter](enclave/src/engine.rs) |
| Build and diagnostics | Adds an enrollment Nix EIF target, host image, native diagnostics and loopback-only browser/test issuer. Deployment publication and promotion live in `tee-apps`. | [Nix target](../nix/enclave-images.nix), [build script](../scripts/build-enclaves.sh), [operator tool](e2e/src/main.rs), [CI](../.github/workflows/rust-ci.yml) |

Assignment contents now match Flamingo's fields: attestation and public key. There is no assignment nonce, reservation table, expiry or consumed-request tracking. The remaining `AdmissionChallenge.nonce` belongs to the host's ticket exchange, never to the Nitro document or sealed image request. The attestation call leaves Nitro's optional nonce field empty.

The common foundation is Pontifex 3 channel encryption, boot-scoped keys, cached Nitro attestation, a host that relays ciphertext, one encrypted request/result per WebSocket, and a worker launched before broker keys or runtime threads. The Minijail policy/process implementation is pre-existing in the PR base; the new trust-sensitive code is the integration listed above.

Enrollment does not produce Flamingo's independently verifiable signed result. `PendingResult::open` decrypts and validates the response and checks its worker metadata; it is not a credential-issuance proof. A caller can submit the same image or ciphertext again during the same boot. Application authorization, freshness and issuance binding remain separate work.

The assignment and sealed-request changes require a matching client/server release. WalletKit's dependency and the deployment source pin must move together with the newly built PCR policy; the previously deployed staging release and its E2E evidence describe the older wire format.

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
