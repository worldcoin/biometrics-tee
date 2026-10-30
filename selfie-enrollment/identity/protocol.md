# Overview

The enclave assembles the enrollment form. Signup-service independently hashes
the received fields and compares the result to the authenticated Nitro nonce.


## Signed fields and HTTP transport

- `nonce`: the 32-byte SHA-256 digest defined below.
- `user_data`: byte `01`, followed by the running worker's 48-byte SHA-384.

- Nitro `public_key`: absent. The channel's boot-key document is separate.
- HTTP `x-tee-attestation`: standard padded base64 of the complete binary
  COSE_Sign1 document. The raw document is bounded at 16 KiB; gateways must accept its base64-expanded
  representation or impose a compatible, explicitly reviewed tighter limit.
- The attestation is not a multipart part and is excluded from its own digest.

## Canonical digest

Start SHA-256 with the exact ASCII bytes `web-authenticator:identity:v1`.
Append `idComm`, then the 17 entries returned by `Form::parts()`, in that fixed
order. For every entry append, in sequence:

1. Four-byte unsigned big-endian byte length of the field name.
2. The exact field-name bytes.
3. Four-byte unsigned big-endian byte length of the field value.
4. The exact field-value bytes.

`idComm` comes from the single query parameter; reject duplicate or unexpected
query/form fields. The proof is raw binary, not base64. Text values are their
submitted UTF-8 bytes, without trimming or normalization. Multipart boundaries,
wire part order, filenames, MIME headers and the attestation header are not
hashed. Multipart order is irrelevant because the verifier uses the fixed
canonical order; reject duplicate fields rather than choosing the first/last.

The ownership proof is nonempty and at most 768 KiB, matching signup-service's
bound and accommodating Oxide's measured 570,464-byte proof. Image and embedding
validation retain their existing bounds.

`tests/fixtures/enrollment-v1.json` is a synthetic cross-language encoding
fixture, not a valid enrollment or Nitro document. Python independently produced
its digest; Rust and Go must reproduce both signed fields exactly. Mutating any
body field or `idComm` must invalidate the nonce. Changing the worker changes
`user_data` and must fail approved-release matching.

## Producer trust and custody

The integration must obtain the capture time, worker measurement, recipient
keys and identity inside their reviewed trust boundaries. In particular,
attesting host-supplied worker hashes or AMPC keys does not authenticate them.
Recipient keys must be covered by the enclave release measurements.

The associated data contains the same plaintext shares encrypted into the form.
A separate custody-package builder must serialize and encrypt that data for
the user before it leaves the enclave. Its decoded associated-data hash must
equal the form's `associated_data_hash`. Credential issuance and later wallet
import are separate operations; this crate does not perform either.
