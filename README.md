## Deep Identifier Migration

WIP

## Sandboxed workers

The dev and Selfie Check enclaves run their workers through [tabernaculum](https://github.com/worldcoin/tabernaculum), pinned by git revision.
It receives the worker bundle, stages the executable at `bin/worker` and runs it under Minijail with its default seccomp policy.
Each enclave owns its worker protocol; tabernaculum's CI runs the bundle, transport and Minijail process tests.

## Selfie Check enrollment

See [selfie-enrollment](selfie-enrollment/README.md) for the separate embedding-extraction application, attestation contract, native/browser client and staging deployment boundary.
