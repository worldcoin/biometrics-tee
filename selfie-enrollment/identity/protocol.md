# Overview

The enclave assembles signup-service's v4-only web enrollment for one capture.
Signup-service hashes the received capture fields and compares the result to the
authenticated Nitro nonce (signup-service#2400, contract version `2`).

Submit to `PUT /api/v2/identity`. There is no v3 identity: no `idComm` query
parameter, commitment hash or v3 proof. Signup-service verifies the Nitro
capture attestation and, synchronously, the v4 ownership proof for the attested
`sub`. A failed verification never falls back to another flow. The route is
disabled until signup-service enables `ENABLE_WEB_IDENTITY_V2`.

## Attestation

- `nonce`: the 32-byte SHA-256 digest below.
- `user_data`: byte `0x01`, followed by the worker's 48-byte SHA-384.
- `public_key`: absent.
- HTTP `x-nitro-attestation`: standard padded base64 of the binary COSE_Sign1 document.
- Maximum binary document: 12,000 bytes (16,000 base64 bytes), leaving room for
  the header name below the staging ALB single-header limit of 16 KiB.

## Request body

Multipart fields, in submission order:

| # | Field | Value | Attested |
|---|---|---|---|
| 1 | `contract_version` | `2` | yes |
| 2 | `sub` | Canonical v4 subject: `0x`, then 1 to 64 lowercase hex digits without a leading zero, nonzero | yes |
| 3 | `capture_id` | Enclave-generated canonical lowercase UUID | yes |
| 4 | `timestamp` | Enclave capture time, canonical decimal Unix seconds | yes |
| 5–7 | `face_embedding_shares_0`, `_1`, `_2` | Standard padded base64 of each party's sealed share | yes, as decoded bytes |
| 8–10 | `face_embedding_version`, `face_embedding_type`, `face_embedding_inference_backend` | Capture metadata | yes |
| 11 | `pcp_version` | Custody format version | yes |
| 12 | `associated_data_hash` | `0x` plus 32 lowercase hex bytes: Oxide's Poseidon2 associated-data hash | yes |
| 13 | `world_id_challenge_id` | Canonical UUID of the enrollment-purpose v4 challenge | no |
| 14 | `world_id_ownership_proof` | Raw proof bytes, as a binary file part, at most 768 KiB | no |

The v4 challenge and proof are mandatory, but they are outside the digest. A
retry can then send a fresh proof for the same capture without another capture
or attestation. Signup-service still enforces the challenge's purpose,
freshness and replay rules, and requires the proof to cover the attested `sub`.

The subject is signed, so the enclave rejects a non-canonical value instead of
normalizing it. Minimize a padded field-element subject, for example from
WalletKit, before it reaches the enclave.

## Canonical digest

Hash the ASCII prefix `web-authenticator:face-enrollment:v2`, then
`@method` = `PUT`, `@path` = `/api/v2/identity`, then the 12 attested fields
in the order above. For the three share fields, hash the decoded ciphertext
bytes after strict canonical base64 validation. All other values are hashed as
sent, in unmodified UTF-8.

Encode each name and value as
`u32be(name length) || name || u32be(value length) || value`.
Lengths count bytes and use unsigned 32-bit big-endian encoding. Multipart
framing, the attestation header, the challenge and the proof are excluded.

[Encoding fixture](tests/fixtures/enrollment-v2.json), copied from
signup-service `face/app-api/nitro/testdata/web-v2.json` at
`88b1fb3d510b9e25710ba1dc4403017464c4f306`. The Rust test reproduces its nonce.

## Response

Signup-service answers `202` with the `capture_id`, its processing status and a
random `polling_token` with its expiry (15 minutes by default). Give the token
to the browser. It polls `GET /api/v2/identity?sub=<sub>` with a single
`Authorization: Bearer <polling_token>` header, and receives the capture status
and, on success, the issued v4 credential.

Retrying the same capture with the same digest returns the same result without
another MPC insertion. Reusing a `capture_id` with different evidence or
ownership returns `409`.
