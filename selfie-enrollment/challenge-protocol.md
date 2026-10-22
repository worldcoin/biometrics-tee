# Draft three-pose challenge contract, version 1

This is the first v0 implementation milestone: shared types, canonical bytes,
nonce commitments and deterministic target generation. It adds no RPC or public
endpoint and does not change the embedding protocol. The generator runs in the
enclave through `PreparedChallenge`; an independent verifier can use the shared
implementation after receiving a nonce reveal in a future protocol.

Contract, generator and evaluator identifiers are each `u16(1)`. Other identifiers
are rejected. Evaluator version 1 is **reserved for the proposed three-pose
evaluator**; no image evaluator or successful biometric verdict exists here.
The policy digest reserves a binding for its eventual calibrated acceptance
policy. Recognizing either field does not authenticate a policy or evaluator.

## Context and canonical encoding

All integers are unsigned, big-endian. Byte arrays are copied verbatim. The
context is exactly 134 bytes, with no map keys, length prefixes, padding or CBOR
wrapper. Truncated or extended encodings are rejected. JSON in the fixture file
is a readable test representation, not an alternative wire encoding.

| Byte offsets (end exclusive) | Field | Encoding |
| --- | --- | --- |
| 0–2 | Contract version | u16 |
| 2–4 | Generator version | u16 |
| 4–6 | Evaluator version | u16 |
| 6–22 | Challenge ID | 16 bytes |
| 22–54 | Session binding | 32 bytes |
| 54–62 | Expiry, Unix milliseconds | u64 |
| 62–94 | Acceptance-policy digest | 32 bytes |
| 94–126 | Randomness-source configuration digest | 32 bytes |
| 126–134 | Randomness round/block number | u64 |

All-zero IDs/digests and zero expiry/round are reserved and rejected. A future
run controller must generate the unique challenge ID, authenticate the session
binding and validate the policy/source digests. Binding a client-supplied string
alone does not authenticate a session. Expiry is bound here but not enforced:
this pure contract has no clock and accepts historical contexts for later audit.

The source digest must identify the exact approved source configuration,
including network/key identity, value encoding and finality/verification policy.
The source and round are selected before committing. This PR neither selects a
provider nor validates its output, its future availability, or a proof that the
commitment preceded it. A provider verifier and commitment-order evidence are
required before exposing a live challenge operation; arbitrary browser/host
randomness must not be accepted as verified randomness.

## Nonce and commitment

`PreparedChallenge::generate` accepts enclave-owned context and obtains exactly
32 nonce bytes from `OsRng` using its fallible API. Existing production startup
checks `nsm-hwrng`. RNG failure returns an error; it has no default, timestamp or
deterministic fallback. The helper retains the original context and nonce. Its
nonce buffer is zeroized on drop and has no Debug, Clone, serialization or reveal
API. The caller supplies the run ID; this helper is not yet a run registry.

Let `C` be the canonical context and `N` the 32-byte secret nonce:

```text
commitment = SHA256(
  ASCII("selfie-enrollment/challenge/commitment/v1") || 0x00 || C || N
)
```

The trailing domain byte is one zero byte, not the two characters backslash/zero.
The digest commits to all context fields and the nonce before the selected
round's randomness is supplied. It is unsigned. Signing, key attestation and
independent evidence of issuance ordering belong to later milestones. A digest
alone provides no timestamp, session authorization or proof of enclave execution.

## Deterministic generation

Let `R` be exactly 32 bytes of externally sourced randomness. A source-specific
adapter must specify how its authenticated output yields these bytes; there is
no implicit hashing, truncation or text parsing in this contract.

Use [RFC 5869 HKDF](https://www.rfc-editor.org/rfc/rfc5869.html) with SHA-256:

```text
PRK  = HMAC-SHA256(key=R, data=N)
info = ASCII("selfie-enrollment/challenge/generation/v1") || 0x00 || C
seed = HMAC-SHA256(key=PRK, data=info || 0x01)
```

This is HKDF-Extract(salt=R, IKM=N), followed by HKDF-Expand(info, L=32). The
implementation uses the HKDF library. Zero nonce/randomness bytes remain valid
primitive inputs for reproducibility; accepting an external value in a live run
requires provider verification, not a nonzero-byte heuristic.

Number the bits of `seed[0]` from least significant (bit 0):

| Bit | 0 | 1 |
| --- | --- | --- |
| 0 | Turn left first | Turn right first |
| 1 | First turn 20 degrees | First turn 25 degrees |
| 2 | Second turn 20 degrees | Second turn 25 degrees |

The plan always contains exactly three targets: frontal reference, first turn,
opposite-side turn. Left/right refer to the person's anatomical sides regardless
of a mirrored preview. Angles are yaw magnitudes from the frontal reference;
pitch/roll, hold duration, tolerances and timing acceptance are unspecified.
These angles are prototype choices requiring calibration, not secure thresholds.
Bits 3–7 and the remaining seed bytes do not affect this version's targets.

Targets encode as exactly six bytes: three `(side, angle)` pairs. Front is
`(0, 0)`; left is side `1`; right is side `2`; turn angles are the literal decimal
byte values `20` or `25`. Only front followed by opposite-side turns is accepted.
For example, front → right 20° → left 25° is hex `000002140119`.

This generator has **eight possible plans (at most three bits of challenge
entropy)**. Different nonces/context/randomness can produce the same targets.
The nonce changes the seed and commitment but cannot guarantee a distinct plan
or defeat an adaptive generator. Three still images cannot establish continuous
motion or hold duration. This is a separate proposed three-image contract, not
parity with face-pad's temporal pose/iris evaluator.

## Integration boundary

The enclave helper is exported as a library module but never called by the
current `State`, host or RPC router. `targets` is pure derivation, not issuance:
it can be called repeatedly and does not lock a randomness value. A later run
controller must retain the canonical context, accept one verified randomness
value, enforce expiry/single use, track the transcript and gate nonce reveal on
permanent closure. Do not send the nonce or derived seed to the browser during
an active run. A reveal protocol must define crash/restart behavior as well.

Signed commitments/results, biometric evidence formats, image evaluation,
authorization, persistence, instruction delivery and the public audit bundle are
deliberately not defined by this first contract. Subsequent signatures must bind
the complete versioned records rather than only the six target bytes.

## Verification

`sealed-types/tests/fixtures/challenge-v1.json` contains ten fixed vectors covering
all eight plans, zero nonce/randomness and maximum u64 expiry/round. Each includes
the input fields and expected canonical context, commitment, **full 32-byte
seed**, and target bytes. Rust tests compare all outputs, so a derivation bug
cannot hide behind a collision in the small target family.

The independent Python standard-library reference checks itself against RFC 5869
test case 1 and reproduces the fixture without importing Rust implementation code:

```sh
python3 selfie-enrollment/sealed-types/tests/fixtures/challenge_reference.py --check
cargo test --locked -p selfie-enrollment-sealed-types -p selfie-enrollment-enclave
```

Tests also reject malformed lengths, unknown versions, reserved empty fields,
invalid targets and RNG failures, and check that every context binding affects
both the commitment and derived seed. No WalletKit build, camera, worker model,
external randomness service or Nitro deployment is needed for this milestone.
