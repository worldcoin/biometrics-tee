"""Prepare and publish the stage DI migration PCR registry."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap


REGISTRY = "approved-pcrs.json"
BUNDLE = "approved-pcrs.sigstore.json"
POINTER = "current.json"
MAX_POINTER_BYTES = 1024
MAX_ARTIFACT_BYTES = 256 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
PCR = re.compile(r"[0-9a-f]{96}")
ETAG = re.compile(r'"[0-9a-f]+(?:-[0-9]+)?"')
KEY_ARN = re.compile(r"arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]{36}")
STAGE_KEY_SHA256 = "1788c6e062a29f6fa4d95f203b07bc4c810a36255ca70be4c090feeaff93bff6"
REKOR_LOG_ID = "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="


def prepare(store, release, candidate, output):
    builds = parse_registry(candidate.read_bytes())
    if len(builds) != 1 or builds[0]["release"] != release:
        raise ValueError("candidate must contain one build for the selected release")
    build = builds[0]

    previous = store.current()
    old_bytes = store.registry(previous["revision"]) if previous else None
    old_builds = parse_registry(old_bytes) if old_bytes is not None else []
    matching = next((item for item in old_builds if item["release"] == release), None)
    if matching is not None and matching != build:
        raise ValueError("this release is already approved with different build metadata")
    registry = old_bytes if matching else json_bytes({"approved_builds": old_builds + [build]})
    revision = sha256(bounded(registry, MAX_ARTIFACT_BYTES))

    output.mkdir(parents=True, exist_ok=True)
    (output / REGISTRY).write_bytes(registry)
    (output / "review.json").write_bytes(json_bytes({"revision": revision, "previous": previous}))
    return revision


def publish(store, kms_key_arn, input_dir, expected_revision):
    review = load_json((input_dir / "review.json").read_bytes(), MAX_POINTER_BYTES)
    if set(review) != {"revision", "previous"}:
        raise ValueError("invalid PCR registry review metadata")
    revision = valid_revision(review["revision"])
    previous = review["previous"]
    if previous is not None:
        valid_pointer(previous)
    registry = bounded((input_dir / REGISTRY).read_bytes(), MAX_ARTIFACT_BYTES)
    if revision != expected_revision or sha256(registry) != revision:
        raise ValueError("PCR registry bytes do not match the reviewed revision")
    parse_registry(registry)

    current = store.current()
    already_current = current is not None and current["revision"] == revision
    if not already_current and current != previous:
        raise ValueError("current registry changed after preparation; start a fresh approval")

    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        key = approval_public_key(kms_key_arn, directory)
        if current is not None:
            validate_published_pair(store, current["revision"], key, directory)
        if already_current:
            return revision

        registry_file = directory / REGISTRY
        bundle_file = directory / BUNDLE
        registry_file.write_bytes(registry)
        existing_registry = store.get(revision_key(revision, REGISTRY), missing_ok=True)
        if existing_registry is not None and existing_registry[0] != registry:
            raise ValueError("registry bytes at this revision do not match the reviewed bytes")
        existing_bundle = store.get(revision_key(revision, BUNDLE), missing_ok=True)
        if existing_bundle is None:
            sign_registry(kms_key_arn, registry_file, bundle_file, directory)
        else:
            bundle_file.write_bytes(existing_bundle[0])
        verify_bundle(registry_file, bundle_file, key)

        if existing_registry is None:
            store.put(revision_key(revision, REGISTRY), registry_file, "--if-none-match", "*")
        if existing_bundle is None:
            store.put(revision_key(revision, BUNDLE), bundle_file, "--if-none-match", "*")
        pointer_file = directory / POINTER
        pointer_file.write_bytes(json_bytes({"revision": revision}))
        condition = ("--if-match", previous["etag"]) if previous else ("--if-none-match", "*")
        store.put(POINTER, pointer_file, *condition)
    return revision


def validate_published_pair(store, revision, public_key, directory):
    registry = directory / REGISTRY
    registry.write_bytes(store.registry(revision))
    bundle = directory / BUNDLE
    bundle.write_bytes(store.get(revision_key(revision, BUNDLE))[0])
    verify_bundle(registry, bundle, public_key)


def approval_public_key(arn, directory):
    if not KEY_ARN.fullmatch(arn):
        raise ValueError("a concrete KMS signing key ARN is required")
    result = aws("kms", "get-public-key", "--key-id", arn)
    der = base64.b64decode(result["PublicKey"], validate=True)
    if (
        result["KeyId"] != arn
        or result["KeySpec"] != "ECC_NIST_P256"
        or result["KeyUsage"] != "SIGN_VERIFY"
        or result["SigningAlgorithms"] != ["ECDSA_SHA_256"]
        or sha256(der) != STAGE_KEY_SHA256
    ):
        raise ValueError("KMS key does not match the stage PCR approval key")
    public_key = directory / "approval.pem"
    lines = textwrap.fill(base64.b64encode(der).decode("ascii"), 64)
    public_key.write_text(f"-----BEGIN PUBLIC KEY-----\n{lines}\n-----END PUBLIC KEY-----\n")
    return public_key


def sign_registry(arn, registry, bundle, directory):
    config = directory / "signing-config.json"
    run(
        "cosign", "signing-config", "create",
        "--rekor", "url=https://rekor.sigstore.dev,api-version=1,start-time=2021-01-12T11:53:27Z,operator=sigstore.dev",
        "--rekor-config", "ANY", "--out", config,
    )
    run(
        "cosign", "sign-blob", "--yes", "--key", f"awskms:///{arn}",
        "--signing-config", config, "--bundle", bundle, registry,
    )


def verify_bundle(registry, bundle, public_key):
    material = load_json(bundle.read_bytes(), MAX_ARTIFACT_BYTES)
    entries = material["verificationMaterial"]["tlogEntries"]
    if not isinstance(entries, list) or len(entries) != 1:
        raise ValueError("bundle must include one Rekor entry")
    entry = entries[0]
    proof = entry.get("inclusionProof")
    if (
        entry["kindVersion"] != {"kind": "hashedrekord", "version": "0.0.1"}
        or entry["logId"]["keyId"] != REKOR_LOG_ID
        or not isinstance(proof, dict)
        or not proof.get("checkpoint", {}).get("envelope")
        or "messageSignature" not in material
    ):
        raise ValueError("bundle must include a Rekor v1 inclusion proof and checkpoint")
    run("cosign", "verify-blob", "--key", public_key, "--bundle", bundle, registry)


class RegistryStore:
    def __init__(self, bucket):
        self.bucket = bucket

    def current(self):
        result = aws(
            "s3api", "list-objects-v2", "--bucket", self.bucket,
            "--prefix", POINTER, "--max-keys", "1", "--no-paginate",
        )
        if not any(item["Key"] == POINTER for item in result.get("Contents", [])):
            return None
        data, etag = self.get(POINTER, limit=MAX_POINTER_BYTES)
        pointer = load_json(data, MAX_POINTER_BYTES)
        if set(pointer) != {"revision"}:
            raise ValueError("invalid current.json")
        return valid_pointer({"revision": pointer["revision"], "etag": etag})

    def registry(self, revision):
        data, _ = self.get(revision_key(revision, REGISTRY))
        if sha256(data) != revision:
            raise ValueError("PCR registry hash does not match its revision")
        return data

    def get(self, key, *, limit=MAX_ARTIFACT_BYTES, missing_ok=False):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "object"
            try:
                result = aws(
                    "s3api", "get-object", "--bucket", self.bucket, "--key", key,
                    "--range", f"bytes=0-{limit}", path,
                )
            except subprocess.CalledProcessError as error:
                if missing_ok and "(NoSuchKey)" in error.stderr:
                    return None
                raise
            return bounded(path.read_bytes(), limit), result["ETag"]

    def put(self, key, path, condition, value):
        aws(
            "s3api", "put-object", "--bucket", self.bucket, "--key", key,
            "--body", path, "--content-type", "application/json", condition, value,
        )


def parse_registry(data):
    registry = load_json(data, MAX_ARTIFACT_BYTES)
    builds = registry.get("approved_builds")
    if set(registry) != {"approved_builds"} or not isinstance(builds, list):
        raise ValueError("invalid approved_builds registry")
    releases = set()
    for build in builds:
        if not isinstance(build, dict) or set(build) != {
            "release", "launcher_image_digest", "eif_digest", "measurements",
        }:
            raise ValueError("invalid approved build fields")
        release = build["release"]
        if not isinstance(release, str) or not release or release in releases:
            raise ValueError("each approved build must have a unique release")
        releases.add(release)
        for field in ("launcher_image_digest", "eif_digest"):
            if not matches(r"sha256:[0-9a-f]{64}", build[field]):
                raise ValueError(f"invalid {field}")
        measurements = build["measurements"]
        if not isinstance(measurements, dict) or set(measurements) != {"PCR0", "PCR1", "PCR2"}:
            raise ValueError("approved build must contain exactly PCR0, PCR1 and PCR2")
        if any(not matches(PCR, value) or value == "0" * 96 for value in measurements.values()):
            raise ValueError("approved measurements must be nonzero 48-byte lowercase hex")
    return builds


def revision_key(revision, filename):
    return f"revisions/{valid_revision(revision)}/{filename}"


def valid_revision(value):
    if not matches(SHA256, value):
        raise ValueError("registry revision must be a lowercase SHA-256 digest")
    return value


def valid_pointer(pointer):
    if (
        not isinstance(pointer, dict)
        or set(pointer) != {"revision", "etag"}
        or not matches(ETAG, pointer["etag"])
    ):
        raise ValueError("invalid reviewed registry pointer")
    valid_revision(pointer["revision"])
    return pointer


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def load_json(data, limit):
    value = json.loads(bounded(data, limit), object_pairs_hook=unique_keys)
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return value


def unique_keys(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("duplicate JSON field")
    return value


def bounded(data, limit):
    if not 0 < len(data) <= limit:
        raise ValueError(f"registry file must be 1–{limit} bytes")
    return data


def json_bytes(value):
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def aws(*args):
    return json.loads(run("aws", "--no-cli-pager", "--output", "json", *args) or "{}")


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_args = commands.add_parser("prepare")
    prepare_args.add_argument("--bucket", required=True)
    prepare_args.add_argument("--release", required=True)
    prepare_args.add_argument("--candidate", type=Path, required=True)
    prepare_args.add_argument("--output", type=Path, required=True)
    publish_args = commands.add_parser("publish")
    publish_args.add_argument("--bucket", required=True)
    publish_args.add_argument("--kms-key-arn", required=True)
    publish_args.add_argument("--input", type=Path, required=True)
    publish_args.add_argument("--expected-revision", required=True)
    args = parser.parse_args()
    store = RegistryStore(args.bucket)
    try:
        if args.command == "prepare":
            print(prepare(store, args.release, args.candidate, args.output))
        else:
            print(publish(store, args.kms_key_arn, args.input, args.expected_revision))
    except subprocess.CalledProcessError as error:
        parser.exit(1, f"{error.cmd[0]} failed: {error.stderr.strip()}\n")
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
