#!/usr/bin/env python3
"""Independent standard-library reference for challenge-v1.json; run with --check."""
import hashlib
import hmac
import json
from pathlib import Path
import struct
import sys


def hkdf(nonce, randomness, info):
    prk = hmac.digest(randomness, nonce, "sha256")
    # This protocol asks for exactly one SHA-256 output block (32 bytes).
    return hmac.digest(prk, info + b"\x01", "sha256")


# RFC 5869, test case 1, truncated to the first 32 output bytes.
assert hkdf(
    b"\x0b" * 22, bytes(range(13)), bytes(range(0xF0, 0xFA))
).hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"

CONTEXT = {
    "challenge_id": bytes(range(16)).hex(),
    "session_binding": bytes(range(32, 64)).hex(),
    "expires_at_unix_ms": 1792692000000,
    "policy_digest": bytes(range(64, 96)).hex(),
    "randomness_source": bytes(range(96, 128)).hex(),
    "randomness_round": 123456,
}


def vector(name, context, nonce, randomness):
    encoded = struct.pack(
        ">16s32sQ32s32sQ",
        bytes.fromhex(context["challenge_id"]),
        bytes.fromhex(context["session_binding"]),
        context["expires_at_unix_ms"],
        bytes.fromhex(context["policy_digest"]),
        bytes.fromhex(context["randomness_source"]),
        context["randomness_round"],
    )
    assert len(encoded) == 128
    commitment = hashlib.sha256(
        b"selfie-enrollment/challenge/commitment/v1\0" + encoded + nonce
    ).digest()
    seed = hkdf(
        nonce, randomness, b"selfie-enrollment/challenge/generation/v1\0" + encoded
    )
    first_side = 1 + (seed[0] & 1)
    responses = bytes(
        [0, 0, first_side, 20 + 5 * ((seed[0] >> 1) & 1),
         3 - first_side, 20 + 5 * ((seed[0] >> 2) & 1)]
    )
    return {
        "name": name,
        "context": context,
        "nonce": nonce.hex(),
        "external_randomness": randomness.hex(),
        "context_hex": encoded.hex(),
        "commitment_hex": commitment.hex(),
        "seed_hex": seed.hex(),
        "target_responses_hex": responses.hex(),
    }


def vectors():
    # Cover all eight plans without relying on a Rust RNG or Rust implementation.
    plans = {}
    for value in range(256):
        candidate = vector("", CONTEXT, bytes([value]) * 32, bytes(range(128, 160)))
        index = bytes.fromhex(candidate["seed_hex"])[0] & 7
        if index not in plans:
            candidate["name"] = f"plan-{index}"
            plans[index] = candidate
        if len(plans) == 8:
            break
    assert len(plans) == 8
    boundary = dict(CONTEXT, expires_at_unix_ms=2**64 - 1, randomness_round=2**64 - 1)
    return [plans[index] for index in range(8)] + [
        vector("zero-nonce-and-randomness", CONTEXT, bytes(32), bytes(32)),
        vector("maximum-u64", boundary, b"\xff" * 32, b"\xff" * 32),
    ]


if __name__ == "__main__":
    expected = json.dumps(vectors(), indent=2) + "\n"
    if sys.argv[1:] == ["--check"]:
        actual = Path(__file__).with_name("challenge-v1.json").read_text()
        if actual != expected:
            sys.exit("challenge-v1.json differs from the independent reference")
        print("10 challenge vectors match the independent reference")
    elif sys.argv[1:]:
        sys.exit("usage: challenge_reference.py [--check]")
    else:
        print(expected, end="")
