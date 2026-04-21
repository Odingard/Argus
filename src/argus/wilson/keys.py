"""
argus/wilson/keys.py — HMAC key lifecycle for Wilson bundles.

Three things:

  1. ``load_key()`` — resolves the active key from (in order):
       env ``ARGUS_WILSON_KEY``
       file at ``ARGUS_WILSON_KEYFILE`` (if set)
       ~/.argus/wilson.key
       built-in default (FOR LOCAL TESTING ONLY — do not ship customer
       bundles signed with the default; the module warns loudly if used
       in a bundle-build path).

  2. ``generate_key()`` — cryptographically-random 32-byte key, hex-encoded.

  3. ``rotate_key()`` — write a new key to ``ARGUS_WILSON_KEYFILE`` or
       ~/.argus/wilson.key, returning (old_fingerprint, new_fingerprint).

There's no CLI subcommand yet — rotate manually via:

    python -c "from argus.wilson.keys import rotate_key; print(rotate_key())"

That plus ``verify_bundle(..., hmac_key=load_key())`` is the full lifecycle.
"""
from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path

_DEFAULT_KEY_DO_NOT_SHIP = (
    b"argus-wilson-default-key-rotate-per-engagement"
)
_KEYFILE_DEFAULT = Path.home() / ".argus" / "wilson.key"


def load_key() -> bytes:
    """Return the active HMAC key bytes."""
    env_val = os.environ.get("ARGUS_WILSON_KEY")
    if env_val:
        return env_val.encode("utf-8")

    env_path = os.environ.get("ARGUS_WILSON_KEYFILE")
    if env_path:
        p = Path(env_path).expanduser()
        if p.exists():
            return p.read_text(encoding="utf-8").strip().encode("utf-8")

    if _KEYFILE_DEFAULT.exists():
        return _KEYFILE_DEFAULT.read_text(encoding="utf-8").strip().encode("utf-8")

    return _DEFAULT_KEY_DO_NOT_SHIP


def key_fingerprint(key: bytes) -> str:
    """Short, public fingerprint of an HMAC key. Safe to log."""
    return hashlib.sha256(key).hexdigest()[:12]


def generate_key() -> str:
    """New 32-byte hex-encoded HMAC key."""
    return secrets.token_hex(32)


def rotate_key(
    keyfile: str | None = None,
) -> tuple[str, str]:
    """
    Rotate the on-disk key. Returns (old_fingerprint, new_fingerprint).
    """
    path = Path(keyfile).expanduser() if keyfile else _KEYFILE_DEFAULT
    old_fp = ""
    if path.exists():
        old_fp = key_fingerprint(path.read_text(encoding="utf-8").strip().encode())

    new_key = generate_key()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(new_key, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

    return (old_fp or "none", key_fingerprint(new_key.encode()))


def is_default_key(key: bytes) -> bool:
    """True if the caller is about to sign with the ship-default. Warn."""
    return key == _DEFAULT_KEY_DO_NOT_SHIP
