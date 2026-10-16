## Deep Identifier Migration

WIP

## Shared sandbox bundle

`di-sandbox` re-exports bundle provisioning from a pinned Flamingo commit.
DI owns its worker protocol, isolation policy and bootstrap acknowledgement.
The shared receiver stages the executable at `bin/verifier-worker`.
The dev enclave instead runs its worker through [tabernaculum](https://github.com/worldcoin/tabernaculum), which stages it at `bin/worker`.

Run `cargo test -p di-sandbox` for bundle compatibility and worker transport tests.

## Selfie Check enrollment

See [selfie-enrollment](selfie-enrollment/README.md) for the separate embedding-extraction application, attestation contract, native/browser client and staging deployment boundary.
