## Deep Identifier Migration

WIP

## Shared sandbox bundle

`di-sandbox` re-exports bundle provisioning from a pinned Flamingo commit.
DI owns its worker protocol, isolation policy and bootstrap acknowledgement.
The shared receiver stages the executable at `bin/verifier-worker`.

Run `cargo test -p di-sandbox` for bundle compatibility and worker transport tests.
