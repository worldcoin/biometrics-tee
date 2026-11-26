import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pcr_registry as registry


def build(release, digit):
    return {
        "release": release,
        "launcher_image_digest": "sha256:" + digit * 64,
        "eif_digest": "sha256:" + digit * 64,
        "measurements": {f"PCR{i}": digit * 96 for i in range(3)},
    }


class Store:
    def __init__(self):
        self.pointer = None
        self.objects = {}
        self.writes = []
        self.fail_on_key = None

    def current(self):
        return self.pointer

    def registry(self, revision):
        return self.objects[registry.revision_key(revision, registry.REGISTRY)]

    def get(self, key, *, missing_ok=False):
        if missing_ok and key not in self.objects:
            return None
        return (self.objects[key], '"abc"')

    def put(self, key, path, condition, value):
        if self.fail_on_key == key:
            raise RuntimeError(f"failed to upload {key}")
        if condition == "--if-match":
            assert key == registry.POINTER and self.pointer["etag"] == value
        else:
            assert (condition, value) == ("--if-none-match", "*") and key not in self.objects
        data = path.read_bytes()
        self.objects[key] = data
        self.writes.append((key, condition, value))
        if key == registry.POINTER:
            self.pointer = {**json.loads(data), "etag": '"abc"'}


class PublicationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.data = Path(directory.name)
        self.store = Store()
        self.review = self.data / "review"
        self.candidate = self.data / "candidate.json"
        sign = patch.object(
            registry, "sign_registry",
            side_effect=lambda _, source, bundle, __: bundle.write_bytes(source.read_bytes()),
        )
        verify = patch.object(
            registry, "verify_bundle",
            side_effect=lambda source, bundle, _: self.assertEqual(source.read_bytes(), bundle.read_bytes()),
        )
        key = patch.object(registry, "approval_public_key")
        for stub in (sign, verify, key):
            self.addCleanup(stub.stop)
        self.sign = sign.start()
        self.verify = verify.start()
        self.key = key.start()

    def prepare(self, release, digit):
        self.candidate.write_bytes(registry.json_bytes({"approved_builds": [build(release, digit)]}))
        return registry.prepare(self.store, release, self.candidate, self.review)

    def publish(self, revision):
        return registry.publish(self.store, "approval-key", "a" * 64, self.review, revision)

    def test_first_and_second_revisions_keep_matches_and_move_pointer_last(self):
        first = self.prepare("v0.1.0", "1")
        self.assertEqual(self.store.writes, [])
        self.publish(first)
        self.assertEqual(
            self.store.writes,
            [
                (registry.revision_key(first, registry.REGISTRY), "--if-none-match", "*"),
                (registry.revision_key(first, registry.BUNDLE), "--if-none-match", "*"),
                (registry.POINTER, "--if-none-match", "*"),
            ],
        )

        second = self.prepare("v0.2.0", "2")
        self.assertNotEqual(first, second)
        self.assertEqual(
            registry.parse_registry((self.review / registry.REGISTRY).read_bytes()),
            [build("v0.1.0", "1"), build("v0.2.0", "2")],
        )
        self.publish(second)
        self.assertEqual(self.store.writes[-1], (registry.POINTER, "--if-match", '"abc"'))
        self.assertEqual(self.store.pointer["revision"], second)
        self.assertEqual(registry.parse_registry(self.store.registry(first)), [build("v0.1.0", "1")])
        with self.assertRaisesRegex(ValueError, "already approved"):
            self.prepare("v0.1.0", "3")

    def test_tampering_and_stale_review_stop_before_signing(self):
        revision = self.prepare("v0.1.0", "1")
        approved = self.review / registry.REGISTRY
        approved.write_bytes(approved.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "reviewed revision"):
            self.publish(revision)

        self.prepare("v0.1.0", "1")
        self.store.pointer = {"revision": "f" * 64, "etag": '"abc"'}
        with self.assertRaisesRegex(ValueError, "changed after preparation"):
            self.publish(revision)
        self.key.assert_not_called()
        self.sign.assert_not_called()
        self.assertEqual(self.store.writes, [])

    def test_retry_reuses_verified_pair_after_pointer_write_failure(self):
        revision = self.prepare("v0.1.0", "1")
        self.store.fail_on_key = registry.POINTER
        with self.assertRaisesRegex(RuntimeError, "failed to upload current.json"):
            self.publish(revision)
        self.assertIsNone(self.store.pointer)
        self.assertEqual(len(self.store.writes), 2)

        self.store.fail_on_key = None
        self.publish(revision)
        self.publish(revision)
        self.sign.assert_called_once()
        self.assertEqual(self.verify.call_count, 3)
        self.assertEqual(len(self.store.writes), 3)

    def test_retry_finishes_missing_bundle_without_overwriting_registry(self):
        revision = self.prepare("v0.1.0", "1")
        bundle_key = registry.revision_key(revision, registry.BUNDLE)
        self.store.fail_on_key = bundle_key
        with self.assertRaisesRegex(RuntimeError, "failed to upload"):
            self.publish(revision)
        self.assertIsNone(self.store.pointer)

        self.store.fail_on_key = None
        self.publish(revision)
        self.assertEqual(self.store.writes[1], (bundle_key, "--if-none-match", "*"))
        self.assertEqual(self.store.pointer["revision"], revision)

    def test_rejects_wrong_release_and_debug_measurements(self):
        valid = build("v0.1.0", "1")
        for bad, error in [
            (valid, "selected release"),
            (dict(valid, measurements={**valid["measurements"], "PCR1": "0" * 96}), "nonzero"),
        ]:
            self.candidate.write_bytes(registry.json_bytes({"approved_builds": [bad]}))
            release = "v0.2.0" if bad is valid else valid["release"]
            with self.assertRaisesRegex(ValueError, error):
                registry.prepare(self.store, release, self.candidate, self.review)
        self.assertFalse(self.review.exists())


class ApprovalKeyTests(unittest.TestCase):
    def test_requires_the_configured_public_key_fingerprint(self):
        arn = "arn:aws:kms:eu-central-1:123456789012:key/01234567-89ab-cdef-0123-456789abcdef"
        der = b"mock KMS public key"
        result = {
            "KeyId": arn,
            "KeySpec": "ECC_NIST_P256",
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": ["ECDSA_SHA_256"],
            "PublicKey": base64.b64encode(der).decode("ascii"),
        }
        with tempfile.TemporaryDirectory() as tmp, patch.object(registry, "aws", return_value=result):
            directory = Path(tmp)
            with self.assertRaisesRegex(ValueError, "expected PCR approval key"):
                registry.approval_public_key(arn, "0" * 64, directory)
            self.assertEqual(list(directory.iterdir()), [])
            key = registry.approval_public_key(arn, registry.sha256(der), directory)
            self.assertEqual(base64.b64decode(key.read_text().splitlines()[1]), der)


if __name__ == "__main__":
    unittest.main()
