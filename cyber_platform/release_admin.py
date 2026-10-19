"""Offline owner administration for signed releases; never executes release content."""
import argparse
import base64
import contextlib
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import signed_release as core
from .store import Problem

MAX_JSON = 32768
MAX_ARTIFACTS = 128 * 1024 * 1024


def _private(info):
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("Private files and directories must belong to the current user with no group/other access")


@contextlib.contextmanager
def _directory(path, *, private=False, create=False):
    """Walk without following any symlink, including ancestor components."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(absolute.parts[1:]):
            final = index == len(absolute.parts) - 2
            try:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not (create and final):
                    raise
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass  # A concurrent verifier may have created it; reopen and validate below.
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        if private:
            _private(os.fstat(fd))
        yield fd
    finally:
        os.close(fd)


def _regular(fd, *, private=False, trust=False):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("A regular file is required")
    if private:
        _private(info)
    if trust and (info.st_uid not in (0, os.getuid()) or stat.S_IMODE(info.st_mode) & 0o022):
        raise ValueError("Trust file must have a trusted owner and must not be writable by group/others")
    return info


def _read_at(directory, name, *, private=False, trust=False, limit=MAX_JSON):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        info = _regular(fd, private=private, trust=trust)
        if info.st_size > limit:
            raise ValueError("File exceeds allowed size")
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("File exceeds allowed size")
        return data
    finally:
        os.close(fd)


def _read(path, **kwargs):
    path = Path(path)
    with _directory(path.parent, private=kwargs.get('private', False)) as fd:
        return _read_at(fd, path.name, **kwargs)


def _exclusive(path, data, *, private_parent=False):
    path = Path(path)
    with _directory(path.parent, private=private_parent) as directory:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(fd)
            os.fsync(directory)
        finally:
            os.close(fd)


def _password():
    password = getpass.getpass("Signing key password (12..256 characters): ")
    if not 12 <= len(password) <= 256:
        raise ValueError("Password must contain 12..256 characters")
    return password.encode('utf-8')


def keygen(private_path, trust_path):
    if os.path.abspath(private_path) == os.path.abspath(trust_path):
        raise ValueError("Private key and public trust paths must differ")
    password = _password()
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    keyid = core.key_id(public)
    trust = {"schema": "was.trust/1", "repository": core.REPOSITORY, "threshold": 1,
             "keys": [{"key_id": keyid, "public_key": base64.b64encode(public).decode('ascii')}]}
    # Check both destinations first; exclusive creation remains the final no-overwrite guard.
    for target in (private_path, trust_path):
        path = Path(target)
        with _directory(path.parent, private=target == private_path) as directory:
            try:
                os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("Output already exists")
    _exclusive(private_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.BestAvailableEncryption(password)), private_parent=True)
    _exclusive(trust_path, core.canonical(trust) + b'\n')
    return {"keyid": keyid, "trust_written": True, "private_key_encrypted": True}


def sign(payload_path, private_path, output_path):
    payload = core.load_json(_read(payload_path))
    core.validate_payload(payload)
    key = serialization.load_pem_private_key(_read(private_path, private=True), password=_password())
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("An encrypted Ed25519 private key is required")
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    keyid = core.key_id(public)
    envelope = {"signed": payload, "signatures": [{"key_id": keyid, "signature": base64.b64encode(key.sign(core.canonical(payload))).decode('ascii')}]}
    encoded = core.canonical(envelope) + b'\n'
    if len(encoded) > MAX_JSON:
        raise ValueError("Signed envelope exceeds allowed size")
    _exclusive(output_path, encoded)
    return {"keyid": keyid, "digest": hashlib.sha256(core.canonical(payload)).hexdigest(), "signed": True}


def _verify_artifacts(directory, entries):
    total = 0
    with _directory(directory) as fd:
        for entry in entries:
            name = entry['name']
            if not isinstance(name, str) or name in ('.', '..') or '/' in name or '\\' in name or not name:
                raise ValueError("Artifact name must be a basename")
            artifact = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                info = _regular(artifact)
                if info.st_size != entry['size'] or total + info.st_size > MAX_ARTIFACTS:
                    raise ValueError("Artifact size mismatch or total exceeds 128 MiB")
                digest, count = hashlib.sha256(), 0
                with os.fdopen(artifact, 'rb', closefd=False) as stream:
                    while True:
                        chunk = stream.read(1024 * 1024)
                        if not chunk:
                            break
                        count += len(chunk)
                        if count > info.st_size or total + count > MAX_ARTIFACTS:
                            raise ValueError("Artifact changed or exceeds allowed size")
                        digest.update(chunk)
                total += count
                if count != entry['size'] or digest.hexdigest() != entry['sha256']:
                    raise ValueError("Artifact hash mismatch")
            finally:
                os.close(artifact)
    return len(entries)


def _save_state(directory, state):
    temporary = '.state-' + secrets.token_hex(16)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(core.canonical(state) + b'\n')
            stream.flush()
            os.fsync(fd)
        os.replace(temporary, 'release-state.json', src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(fd)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def run_verify(envelope_path, trust_path, commit, state_path, *, artifacts=None, record=False, expected_trust_digest=None):
    envelope = core.load_json(_read(envelope_path))
    trust = core.load_json(_read(trust_path, trust=True))
    with _directory(state_path, private=True, create=True) as directory:
        lock = os.open('release.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
        try:
            _regular(lock, private=True)
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                previous = core.load_json(_read_at(directory, 'release-state.json', private=True))
            except FileNotFoundError:
                previous = None
            verified = core.verify(envelope, trust, expected_commit=commit, previous=previous)
            trust_digest = hashlib.sha256(core.canonical(trust)).hexdigest()
            if expected_trust_digest is not None:
                if not isinstance(expected_trust_digest, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_trust_digest):
                    raise ValueError("Expected trust digest must be a lowercase SHA256 digest")
                if trust_digest != expected_trust_digest:
                    raise ValueError("Trust does not match pinned digest")
            count = _verify_artifacts(artifacts, verified['payload']['artifacts']) if artifacts is not None else 0
            if record:
                _save_state(directory, verified['next_state'])
            payload = verified['payload']
            return {"version": payload['version'], "commit": payload['commit'], "sequence": payload['sequence'],
                    "digest": verified['digest'], "signers": verified['signers'], "artifacts_verified": count,
                    "trust_digest": trust_digest,
                    "recorded": record}
        finally:
            os.close(lock)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('keygen')
    create.add_argument('private_key')
    create.add_argument('public_trust')
    signing = commands.add_parser('sign')
    signing.add_argument('payload')
    signing.add_argument('private_key')
    signing.add_argument('output')
    verify = commands.add_parser('verify')
    verify.add_argument('envelope')
    verify.add_argument('trust')
    verify.add_argument('--commit', required=True)
    verify.add_argument('--state', required=True)
    verify.add_argument('--artifacts')
    verify.add_argument('--trust-digest')
    verify.add_argument('--record', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.command == 'keygen':
            result = keygen(args.private_key, args.public_trust)
        elif args.command == 'sign':
            result = sign(args.payload, args.private_key, args.output)
        else:
            result = run_verify(args.envelope, args.trust, args.commit, args.state, artifacts=args.artifacts,
                                record=args.record, expected_trust_digest=args.trust_digest)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    except (OSError, ValueError, TypeError, KeyError, Problem) as exc:
        # Do not include supplied file content, passwords, or private key material.
        parser.exit(1, "Release administration failed: " + type(exc).__name__ + "\n")


if __name__ == '__main__':
    main()
