# Overview

The enclave assembles the enrollment form. Signup-service hashes the received
fields and compares the result to the authenticated Nitro nonce.

## Attestation

- `nonce`: the 32-byte SHA-256 digest below.
- `user_data`: byte `0x01`, followed by the worker's 48-byte SHA-384.
- `public_key`: absent.
- HTTP `x-tee-attestation`: standard padded base64 of the binary COSE_Sign1 document.

## Canonical digest

Hash the ASCII prefix `web-authenticator:identity:v1`, then the query field
`idComm`, then these 17 multipart fields in order:

1. `capture_id`
2. `timestamp`
3. `face_embedding_shares_0`
4. `face_embedding_shares_1`
5. `face_embedding_shares_2`
6. `face_embedding_shares_0_hash`
7. `face_embedding_shares_1_hash`
8. `face_embedding_shares_2_hash`
9. `face_embedding_version`
10. `face_embedding_type`
11. `face_embedding_inference_backend`
12. `pcp_version`
13. `id_commitment_hash`
14. `associated_data_hash`
15. `sub`
16. `world_id_challenge_id`
17. `world_id_ownership_proof`

Encode each field, including `idComm`, as
`u32be(name length) || name || u32be(value length) || value`.
Lengths count bytes and use unsigned 32-bit big-endian encoding. Text uses
unmodified UTF-8; the ownership proof uses raw binary. Multipart framing and
the attestation header are excluded.

[Encoding fixture](tests/fixtures/enrollment-v1.json).
