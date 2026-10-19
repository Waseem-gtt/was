"""Opt-in full signed release exercise using temporary keys, never owner keys.

Run from a prepared private checkout:
  python -m tests.release_end_to_end REVIEWED_SHA NEW_TEST_PREFIX
Requires the release.sh prerequisites and network access for its pinned checks.
The prefix must not exist; it remains test-only with a temporary trust pin.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cyber_platform import __version__, release_admin, signed_release


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("commit")
    parser.add_argument("test_prefix")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{40}", args.commit):
        parser.error("A complete reviewed commit SHA is required")
    prefix = Path(args.test_prefix).absolute()
    if prefix.exists() or prefix.is_symlink():
        parser.error("Use a new test-only prefix, never a live release directory")
    repository = Path(__file__).resolve().parent.parent
    runner = repository / "scripts/release.sh"
    os.umask(0o077)
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        source = root / "source.zip"
        subprocess.run(["git", "archive", "--format=zip", "-o", str(source), args.commit], cwd=repository, check=True)
        now = int(time.time())
        payload = {"schema": "was.release/1", "repository": signed_release.REPOSITORY,
                   "sequence": 10, "version": __version__, "commit": args.commit,
                   "issued_at": now - 1, "expires_at": now + 3600,
                   "artifacts": [{"name": source.name, "size": source.stat().st_size,
                                  "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}]}

        def fixture(key, data, name):
            public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            identifier = signed_release.key_id(public)
            trust = {"schema": "was.trust/1", "repository": signed_release.REPOSITORY, "threshold": 1,
                     "keys": [{"key_id": identifier, "public_key": base64.b64encode(public).decode()}]}
            envelope = {"signed": data, "signatures": [{"key_id": identifier,
                        "signature": base64.b64encode(key.sign(signed_release.canonical(data))).decode()}]}
            envelope_path, trust_path = root / (name + ".json"), root / (name + "-trust.json")
            envelope_path.write_bytes(signed_release.canonical(envelope))
            trust_path.write_bytes(signed_release.canonical(trust))
            return envelope_path, trust_path

        key = Ed25519PrivateKey.generate()  # Ephemeral test-only key; never serialized.
        envelope, trust = fixture(key, payload, "fixture")
        verified = release_admin.run_verify(envelope, trust, args.commit, root / "artifact-state", artifacts=root)
        assert verified["artifacts_verified"] == 1

        def command(operation, metadata=None, trusted=None, *, accepted=True):
            argv = ["bash", str(runner), operation, args.commit, str(prefix)]
            if metadata is not None:
                argv += ["--signed", str(metadata), str(trusted)]
            result = subprocess.run(argv, cwd=repository, capture_output=not accepted)
            assert (result.returncode == 0) == accepted, (operation, result.returncode)

        command("prepare", envelope, trust)
        assert not (prefix / "signature-state/release-state.json").exists()
        command("activate", envelope, trust)
        state_path = prefix / "signature-state/release-state.json"
        original_state = state_path.read_bytes()
        command("activate", accepted=False)
        lower, lower_trust = fixture(key, {**payload, "sequence": 9}, "lower")
        command("activate", lower, lower_trust, accepted=False)
        substituted, substitute_trust = fixture(Ed25519PrivateKey.generate(), {**payload, "sequence": 11}, "substitute")
        command("activate", substituted, substitute_trust, accepted=False)
        command("activate", envelope, trust)  # Identical retry is safe.
        assert state_path.read_bytes() == original_state
        assert (prefix / "current").resolve() == prefix / "releases" / args.commit
        print(json.dumps({"source_commit": args.commit, "signed_prepare": True, "signed_activation": True,
                          "source_artifact_checked": True, "unsigned_activation_rejected": True,
                          "sequence_downgrade_rejected": True, "trust_substitution_rejected": True,
                          "idempotent_retry": True, "temporary_test_keys_only": True}))


if __name__ == "__main__":
    main()
