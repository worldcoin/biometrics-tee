# Native enrollment producer

`State::prepare_enrollment` is a blocking enclave operation that reuses the
existing worker and processing semaphore. It extracts from the supplied PNG,
creates its capture ID and clock timestamp locally, obtains authorization from
the enclave-resident identity source, calls `assemble` once and encrypts the
same associated data for custody. Returned values contain submission fields and
ciphertext, not the original image, raw embedding or plaintext shares.

`NsmAttestor` implements the per-capture adapter through Pontifex's existing
`SecureModule::raw_attest`: signed nonce is the request digest, signed user_data
is version 1 plus the worker SHA-384, and public_key is absent. It does not reuse
the cached channel-key document.

## Activation prerequisites

This native entry point is deliberately not registered as a new public RPC or
WebSocket route by this draft. The embedding-only API remains unchanged.

- Supply a real enclave-held v3 identity/proof implementation of `IdentitySource`,
  including secret retention, credential retrieval and retry lifecycle. No fake
  implementation exists outside unit tests.
- Build the AMPC recipient keys into the measured enclave. Construct
  `TrustedContext` from those keys and the verified bootstrap worker measurement,
  not host environment variables or request fields.
- Carry the subject/proof, PNG and user's custody key through the verified sealed
  channel. Bind the key to that session; do not let the relay choose it.
- Add bounded sealed request/result types, host/native/browser adapters and
  matching SDK/release policy. Existing 64 KiB embedding response limits cannot
  carry an enrollment proof and encrypted custody package.
- Implement JPEG-to-PNG conversion inside the enclave if using the current web
  camera's JPEG output. This operation accepts PNG only and passes exactly those
  bytes to extraction and custody assembly.
- Test an approved measured Nitro release against signup-service's verifier,
  then complete subject authorization, replay handling, issuance and wallet import.

Those are required production integration tasks. The local tests exercise the
native composition with a synthetic engine/identity/document and real custody
encryption; they do not establish a live Nitro or liveness result.
