# Oxide share fixture

`oxide-shares.json` contains the complete serialized shares in recipient order
0, 1, 2, produced by [`FaceAMPCShareV1_0::from_embedding` at Oxide
3286818](https://github.com/worldcoin/oxide/blob/32868184652c894d3bd2e7c5580dfff94f2a90a7/oxide/src/api/pop_face_backend_api/face_embedding_shares.rs).

Generation used that implementation and its `from_bytes` encoder verbatim in an
isolated runner, with `thread_rng()` replaced by `StdRng::seed_from_u64(42)`.
The runner used Oxide's pinned `ampc-common` revision
`3062538f0307471ed0dd2be8258952c807747141`, rand 0.8.8, base64 0.22.1, and
serde_json 1.0.151. It did not call `embedding_shares::generate`.

The synthetic input repeats `[0, 0, -2, 2, -2, 2, -6, 6, -8, 7, -8, 7, 0, 0,
7, -8, -7]` to fill 512 values; PCP version is `"1"`. These are the frozen
quantized values for `CASES` in `tests/shares.rs`. Serialize the resulting
three-element array with `serde_json::to_string` to reproduce the fixture.
