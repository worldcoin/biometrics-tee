# DI worker protocol

The IPC contract between the DI enclave and the sandboxed `biometric-engines-worker`.

It is a wire-compatible subset of `biometric-engines-protocol` from the private
`worldcoin/biometric-engines` repository, at the commit named in `Cargo.toml`:

- `proto/migration.proto`, `src/migration.rs` and `src/framing.rs` are verbatim; `tests/migration.rs` is verbatim apart from the crate name.
- `proto/biometric_engines.proto` keeps only the migration operation of the envelope, with upstream's field numbers.
  The worker's other operations and failure kinds are unknown fields here and are skipped.
- `src/lib.rs` and `src/protobuf.rs` drop the face-domain code.

`tests/wire.rs` pins the envelope field numbers. Keep it passing when re-syncing from upstream.
