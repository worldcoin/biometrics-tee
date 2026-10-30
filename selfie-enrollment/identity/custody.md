# Encrypted web face custody package v1

`custody::encrypt(&enrollment, &custody_key, rng)` consumes the result of
`assemble` by reference. It generates no new shares and rejects associated data
whose hash or capture/identity metadata differs from the enrollment form.
The caller obtains the user's X25519 custody key through the authenticated,
encrypted enrollment session. This function validates key suitability, not key
ownership. The host must never choose or replace it.

The only returned artifact is a standard libsodium-compatible sealed box of a
gzip tar archive. The archive retains mobile's associated-data paths:

- `associated_data/info.json`: identity commitment, capture ID and Unix seconds.
- `associated_data/face_embeddings.json`: the single original worker embedding.
- `associated_data/face_image.png`: the original PNG supplied to assembly.
- `associated_data/face_ampc_share_{0,1,2}.json`: the exact plaintext shares.

Web-specific files make the evidence and version explicit:

- `manifest.json`: format `web-face-custody-v1`, PCP version and associated-data hash.
- `enrollment.json`: `id_commitment` and the canonical form parts, with values
  encoded as standard base64 so the proof remains byte-exact.
- `attestation/nitro.cose`: the per-capture Nitro document, not a Gateway signature.

This is a versioned web container, not a drop-in legacy Oxide tarball. It does
not write `signed_hashes_attestation_gw.sign` or manufacture a credential.
Wallet import must recognize this format, verify the enrollment binding and
associated-data hash, and attach/import the issued credential after signup-service
completes enrollment. Existing mobile readers must not silently accept it as
Gateway-authenticated custody data.

Plaintext serialization uses fixed backing buffers whose owned contents are
zeroized when dropped. The archive is bounded before allocation and encryption.
Private input types have no Debug implementation; errors contain no payloads.
The sealed ciphertext can be relayed/stored by the host without revealing the
image, embedding or plaintext shares.

Integration remains separate: the enclave must call this while it holds the
extraction/assembly data and erase it before returning. It must not serialize
`AssociatedData` into a public response. The existing embedding-only protocol
is unchanged by this library addition.
