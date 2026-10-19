"""Signature, scope, freshness and rollback regressions for offline releases."""
import base64
import copy
import hashlib
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cyber_platform.signed_release import (
    MAX_JSON, MAX_LIFETIME, REPOSITORY, canonical, key_id, load_json,
    validate_payload, verify,
)
from cyber_platform.store import Problem


class SignedReleaseTests(unittest.TestCase):
    def setUp(self):
        self.private = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.keys = []
        for private in self.private:
            raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            self.keys.append({"key_id": key_id(raw), "public_key": base64.b64encode(raw).decode()})
        self.trust = {"schema": "was.trust/1", "repository": REPOSITORY, "threshold": 1, "keys": self.keys[:2]}
        self.payload = {"schema": "was.release/1", "repository": REPOSITORY, "sequence": 5,
                        "version": "0.8.0", "commit": "a" * 40, "issued_at": 1000,
                        "expires_at": 2000, "artifacts": [{"name": "was-0.8.0.whl", "sha256": "b" * 64, "size": 123}]}

    def envelope(self, payload=None, signers=(0,)):
        signed = copy.deepcopy(self.payload if payload is None else payload)
        return {"signed": signed, "signatures": [
            {"key_id": self.keys[i]["key_id"], "signature": base64.b64encode(self.private[i].sign(canonical(signed))).decode()}
            for i in signers]}

    def check(self, envelope=None, **kwargs):
        return verify(self.envelope() if envelope is None else envelope, self.trust, now=1500, **kwargs)

    def test_round_trip_exact_digest_and_unshared_payload(self):
        envelope = self.envelope()
        result = self.check(load_json(canonical(envelope)))
        self.assertEqual(result["digest"], hashlib.sha256(canonical(self.payload)).hexdigest())
        self.assertEqual(result["signers"], [self.keys[0]["key_id"]])
        self.assertEqual(result["next_state"]["sequence"], 5)
        result["payload"]["version"] = "1.0.0"
        self.assertEqual(envelope["signed"]["version"], "0.8.0")

    def test_strict_json_bounds_encoding_and_duplicates(self):
        invalid = [b'{"a":1,"a":2}', b'{"a":{"b":1,"b":2}}', b'{"a":NaN}',
                   b'{"a":Infinity}', b'[]', b'\xff', b'{} trailing', b' ' * (MAX_JSON + 1),
                   '{"a":"\ud800"}', b'[' * 1100 + b']' * 1100, None]
        for data in invalid:
            with self.subTest(data=repr(data)[:80]), self.assertRaises(Problem):
                load_json(data)
        self.assertEqual(load_json('{"نص":1}'), {"نص": 1})
        self.assertEqual(canonical({"b": 1, "a": "نص"}), '{"a":"نص","b":1}'.encode("utf-8"))
        with self.assertRaises(Problem):
            canonical({"a": float("nan")})

    def test_payload_unknown_fields_types_schema_scope_and_names(self):
        cases = [("schema", "was.release/2"), ("repository", "other/was"), ("sequence", True),
                 ("sequence", 0), ("sequence", 2**63), ("issued_at", False), ("expires_at", "2000"),
                 ("version", "01.8.0"), ("version", "0.8"), ("version", "0.8.0;id"),
                 ("version", "1000000.0.0"), ("commit", "A" * 40), ("commit", "a" * 39),
                 ("artifacts", []), ("artifacts", {}), ("unexpected", True)]
        for field, value in cases:
            payload = copy.deepcopy(self.payload)
            payload[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(Problem):
                validate_payload(payload)
        for name in ("../was.whl", "/tmp/was", "a\\b.whl", "a..whl", "a\n", ".", "-start", "x" * 121):
            payload = copy.deepcopy(self.payload)
            payload["artifacts"][0]["name"] = name
            with self.subTest(name=name), self.assertRaises(Problem):
                validate_payload(payload)
        for field, value in (("size", True), ("size", -1), ("size", 128 * 1024 * 1024 + 1),
                             ("sha256", "B" * 64), ("unexpected", 1)):
            payload = copy.deepcopy(self.payload)
            payload["artifacts"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(Problem):
                validate_payload(payload)
        payload = copy.deepcopy(self.payload)
        payload["artifacts"] *= 2
        with self.assertRaises(Problem):
            validate_payload(payload)

    def test_time_window_and_maximum_lifetime(self):
        for issued, expires in ((1501, 2000), (1000, 1500), (1000, 1000),
                                (1000, 1000 + MAX_LIFETIME + 1), (0, 2000)):
            payload = dict(self.payload, issued_at=issued, expires_at=expires)
            with self.subTest(issued=issued, expires=expires), self.assertRaises(Problem):
                self.check(self.envelope(payload))
        self.check(self.envelope(dict(self.payload, issued_at=1500)))
        self.check(self.envelope(dict(self.payload, expires_at=1000 + MAX_LIFETIME)))
        with self.assertRaises(Problem):
            verify(self.envelope(), self.trust, now=True)

    def test_tampering_missing_invalid_unknown_or_duplicate_signatures(self):
        envelope = self.envelope()
        envelope["signed"]["artifacts"][0]["size"] += 1
        with self.assertRaises(Problem):
            self.check(envelope)
        for signatures in ([], self.envelope(signers=(0, 0))["signatures"],
                           self.envelope(signers=(0, 2))["signatures"],
                           [{"key_id": self.keys[0]["key_id"], "signature": "!" * 88}],
                           [{"key_id": self.keys[0]["key_id"], "signature": base64.b64encode(b'x' * 64).decode()}]):
            envelope = self.envelope()
            envelope["signatures"] = signatures
            with self.subTest(signatures=signatures), self.assertRaises(Problem):
                self.check(envelope)
        envelope = self.envelope()
        envelope["unexpected"] = True
        with self.assertRaises(Problem):
            self.check(envelope)
        envelope = self.envelope()
        envelope["signatures"][0]["signature"] = "A" * (MAX_JSON + 1)
        with self.assertRaises(Problem):
            self.check(envelope)
        envelope = self.envelope()
        del envelope["signed"]["commit"]
        with self.assertRaises(Problem):
            self.check(envelope)

    def test_threshold_and_trusted_key_rotation(self):
        self.trust["threshold"] = 2
        with self.assertRaises(Problem):
            self.check()
        result = self.check(self.envelope(signers=(1, 0)))
        self.assertEqual(result["signers"], sorted(k["key_id"] for k in self.keys[:2]))
        self.trust["keys"] = self.keys[1:]
        self.trust["threshold"] = 1
        self.check(self.envelope(signers=(2,)))
        with self.assertRaises(Problem):
            self.check(self.envelope(signers=(0,)))

    def test_trust_rejects_mismatch_duplicates_scope_and_threshold(self):
        for field, value in (("threshold", True), ("threshold", 0), ("threshold", 3),
                             ("schema", "was.trust/2"), ("repository", "other/repo"), ("extra", 1)):
            trust = copy.deepcopy(self.trust)
            trust[field] = value
            with self.subTest(field=field), self.assertRaises(Problem):
                verify(self.envelope(), trust, now=1500)
        for mutate in (lambda t: t["keys"][0].update(key_id="a" * 64),
                       lambda t: t["keys"].append(t["keys"][0]),
                       lambda t: t["keys"][0].update(public_key="a" * 44),
                       lambda t: t["keys"][0].update(extra=True)):
            trust = copy.deepcopy(self.trust)
            mutate(trust)
            with self.assertRaises(Problem):
                verify(self.envelope(), trust, now=1500)
        with self.assertRaises(Problem):
            key_id(b"too short")

    def test_commit_pin_and_rollback_idempotency(self):
        result = self.check(expected_commit="a" * 40)
        state = result["next_state"]
        self.assertEqual(self.check(previous=state)["next_state"], state)
        self.check(self.envelope(dict(self.payload, sequence=6)), previous=state)
        for commit in ("b" * 40, "invalid"):
            with self.assertRaises(Problem):
                self.check(expected_commit=commit)
        for payload in (dict(self.payload, sequence=4), dict(self.payload, version="0.8.1")):
            with self.assertRaises(Problem) as raised:
                self.check(self.envelope(payload), previous=state)
            self.assertEqual(raised.exception.status, 409)
        for field, value in (("schema", "bad"), ("repository", "other/repo"), ("sequence", True),
                             ("digest", "x" * 64), ("extra", 1)):
            previous = dict(state)
            previous[field] = value
            with self.subTest(field=field), self.assertRaises(Problem):
                self.check(previous=previous)


if __name__ == "__main__":
    unittest.main()
