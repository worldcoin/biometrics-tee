# Face PCP with Nitro attestation

`custody::encrypt(&enrollment, &custody_key, rng)` consumes the result of
`assemble` by reference. It generates no new shares and rejects associated data
whose hash or capture metadata differs from the enrollment form.
The caller obtains the user's X25519 custody key through the authenticated,
encrypted enrollment session. This function validates key suitability, not key
ownership. The host must never choose or replace it.

The only returned artifact is a standard libsodium-compatible sealed box of a
gzip tar archive. The archive retains mobile's associated-data paths:

- `associated_data/info.json`: capture ID and Unix seconds. There is no identity
  commitment: the web enrollment has no v3 identity (signup-service#2400).
- `associated_data/face_embeddings.json`: the single original worker embedding.
- `associated_data/face_image.png`: the original PNG supplied to assembly.
- `associated_data/face_ampc_share_{0,1,2}.json`: the exact plaintext shares.

The PCP retains its existing `pcp_version`. Additional files carry the
enrollment binding and Nitro evidence:

- `manifest.json`: PCP version and associated-data hash.
- `enrollment.json`: the v2 form parts in submission order (`contract_version`
  and `sub` included), with values encoded as standard base64 so the proof remains
  byte-exact. A reader recomputes the attested digest from the 12 capture parts
  with `@method` `PUT` and `@path` `/api/v2/identity`, as `protocol.md` defines.
- `attestation/nitro.cose`: the per-capture Nitro document, not a Gateway signature.

This is a Face PCP carrying Nitro evidence; it has no separate browser-specific
format identifier. The evidence entry distinguishes it from the existing
Gateway-backed Face PCP, which requires `signed_hashes_attestation_gw.sign`.
It does not write that Gateway signature or manufacture a credential.

Reader support remains required. Oxide's existing `extract_face_credential`
requires the Gateway signature file and rejects this archive. Its importer must
also accept an `info.json` without `id_commitment`. A Nitro-aware
reader must explicitly handle `attestation/nitro.cose`, require the manifest and
enrollment record, verify the attestation and enrollment binding, and compare the
PCP version and associated-data hash with the attested form. Missing or mixed
Gateway/Nitro evidence must be rejected. The issued credential is attached/imported
after signup-service completes enrollment, using the existing `credential.json`
entry. Removing the browser-specific name does not change these reader requirements.

Plaintext serialization uses fixed backing buffers whose owned contents are
zeroized when dropped. The archive is bounded before allocation and encryption.
Private input types have no Debug implementation; errors contain no payloads.
The sealed ciphertext can be relayed/stored by the host without revealing the
image, embedding or plaintext shares.

Integration remains separate: the enclave must call this while it holds the
extraction/assembly data and erase it before returning. It must not serialize
`AssociatedData` into a public response. The existing embedding-only protocol
is unchanged by this library addition.
