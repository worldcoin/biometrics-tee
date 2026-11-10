# Migration PCP construction

Source Iris files are optional. A present `iris_codes.json` must contain both
iris codes and both mask codes. Each present share file must contain the four
corresponding share fields. Each share Iris version must match the codes' Iris
version when both are present. Share versions are not compared with each other.
Version fields, including `IRIS_shares_version`, may be absent. The shared builder's
compatibility mode preserves absent files and version fields; it still validates
payload fields when constructing Iris inputs.

The enclave checks this contract after source integrity verification and before
biometric inference. Invalid source Iris data produces `InvalidSourceIrisData`
and the job reason `invalid_source_iris_data`. The builder adapter repeats the
check for direct callers. Fresh face/DI outputs retain their separate validation.
Required pipeline images remain mandatory.

TEE supplies the shared builder with Alkali sealed-box encryption using
Curve25519/XSalsa20-Poly1305. Each call uses fresh ephemeral keys and the exact
recipient bytes, with the standard 48-byte ciphertext overhead. Invalid recipients
and library failures propagate through `BuildError::Build` as typed encryption
errors.

`build` consumes the prepared face/DI outputs and normalized image buffers.
Preflight borrows these inputs and validates image coverage without copying image
bytes. Source captures are copied once into the shared builder so the opened source
remains available for preservation checks. Tests retain independent expected
outputs for completion checks. The shared builder zeroizes its owned image buffers
and backend-key values on drop.

The host exposes observed failures through `migration.host.job_failures` with
`reason=invalid_source_iris_data`, including failures whose job update cannot be
persisted. The encrypted diagnostic identifies the migration stage and failure.
Source values and upstream validation text are not included in this error.
`migration.host.job_outcomes` counts observed migrated/failed attempts, including
jobs that expire in the queue, before persistence. Use it as the denominator for
the overall source-Iris rejection rate; it is not a count of unique users or only
packages that reached Iris validation.
`migration.host.queued_requests` reports the host's queue occupancy, including
both waiting and running jobs, and can be compared with the configured queue
capacity.
`migration.host.job_duration_seconds` measures from the database row's creation
timestamp through the host's outcome handling, including upload and queue wait.
It is tagged by `outcome` (`migrated` or `failed`) and excludes optional debug
report upload time.

## Release compatibility

Deploy readers that recognize `invalid_source_iris_data` before enabling its
producer. This includes API/storage readers and the client versions consuming
migration status. Readers that reject unknown reasons cannot read a failed job
containing this value. A rollback must retain reason-reading compatibility for
already persisted jobs. Monitor the rejection rate and user impact during a
bounded canary before expanding the rollout.

## Private sample checks

The sample test rebuilds source packages with synthetic prepared biometric
outputs and verifies preserved artifacts and manifest integrity. It does not run
inference or establish real-model parity. Keep samples and their inventory out of
version control.

Set `PCP_SAMPLES_DIR` to a directory with
`<version>/<sample>/pcp_pkg/` entries. Set `PCP_SAMPLES_EXPECTATIONS` to a JSON
object mapping every relative package directory to an expected outcome:

```json
{
  "2.1/synthetic-example/pcp_pkg": "migrated"
}
```

Allowed outcomes are `migrated`, `unsupported_version`, `missing_thumbnail` and
`invalid_source_iris_data`. Missing or unlisted cases fail the test. The inventory
must be reviewed against the source corpus before running the candidate.

```sh
cargo test --locked -p di-migration-pcp --test samples -- --ignored
```

Run the same corpus against the baseline and candidate. Retained captures and
accepted Iris files must match exactly. Check generated content against the
prepared biometric outputs; randomized ciphertext and salts need not match.
Full worker replay, trusted signature verification and client import/readback are
additional release gates.
