"""Session-record integrity envelope (prototype).

Design goals
------------
Bind every stored session record to:

* the session id (sid)            -> record-swap between sids is detected
* an application namespace       -> records copied from another app are rejected
* a payload format version       -> a format change invalidates old envelopes
* an issued-at / expiry time     -> stale / replayed records can be rejected
* a key id + HMAC                -> keys can be rotated and retired

This module provides *integrity and authenticity only*. The payload is still
plaintext msgpack; an attacker who can read storage can read every value.
Confidentiality would require authenticated encryption (e.g. Fernet / AES-GCM),
which is a separate, additional control.
"""

from __future__ import annotations

import hmac
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Dict, Optional

import msgspec


class IntegrityError(Exception):
    """Base class for envelope verification failures."""


class TamperError(IntegrityError):
    """The envelope or payload was modified after signing."""


class ContextMismatchError(IntegrityError):
    """The envelope does not match the requested sid / namespace / version."""


class ExpiredError(IntegrityError):
    """The envelope passed its expiry timestamp."""


class KeyRetiredError(IntegrityError):
    """The signing key is no longer in the active key ring."""


@dataclass(frozen=True)
class SigningKey:
    kid: str
    secret: bytes
    retired: bool = False


class KeyRing:
    """Holds the active signing key plus verifier keys for rotation.

    * ``signing_key`` is used to mint new envelopes.
    * Every key in ``keys`` may verify; keys flagged ``retired=True`` only
      verify when ``allow_retired`` is passed, so a retired key can be refused
      outright instead of silently trusting legacy records.
    """

    def __init__(self, signing_key: SigningKey, keys: Optional[Dict[str, SigningKey]] = None):
        self.keys: Dict[str, SigningKey] = {signing_key.kid: signing_key}
        if keys:
            self.keys.update(keys)
        self.signing_kid = signing_key.kid

    def signer(self) -> SigningKey:
        key = self.keys[self.signing_kid]
        if key.retired:
            raise KeyRetiredError(f"signing key {key.kid!r} is retired")
        return key

    def verifier(self, kid: str, allow_retired: bool = False) -> SigningKey:
        try:
            key = self.keys[kid]
        except KeyError as exc:
            raise KeyRetiredError(f"unknown key id {kid!r}") from exc
        if key.retired and not allow_retired:
            raise KeyRetiredError(f"key {kid!r} has been retired")
        return key

    def rotate(self, new_key: SigningKey) -> None:
        """Promote ``new_key``; the old signer stays available to verify."""
        self.keys[new_key.kid] = new_key
        self.signing_kid = new_key.kid


# envelope field layout, versioned so the structure itself can evolve
ENVELOPE_VERSION = 1
_ENCODER = msgspec.msgpack.Encoder()
_DECODER = msgspec.msgpack.Decoder()


def _mac_input(
    *,
    sid: str,
    namespace: str,
    format_version: int,
    issued_at: int,
    expires_at: Optional[int],
    payload: bytes,
) -> bytes:
    # length-prefixed fields so no ambiguity from concatenation
    parts = [
        b"session-integrity-v1",
        str(len(sid)).encode(),
        sid.encode(),
        str(len(namespace)).encode(),
        namespace.encode(),
        str(format_version).encode(),
        str(issued_at).encode(),
        b"-" if expires_at is None else str(expires_at).encode(),
        payload,
    ]
    return b"|".join(parts)


def _mac(key: bytes, mac_input: bytes) -> bytes:
    return hmac.new(key, mac_input, sha256).digest()


def seal(
    *,
    sid: str,
    namespace: str,
    format_version: int,
    payload: bytes,
    keyring: KeyRing,
    ttl_seconds: Optional[int],
    now: Optional[int] = None,
) -> bytes:
    """Wrap a serialized session dict in a signed envelope (msgpack bytes)."""
    current = int(time.time()) if now is None else now
    expires_at = None if ttl_seconds is None else current + ttl_seconds
    key = keyring.signer()
    mac_input = _mac_input(
        sid=sid,
        namespace=namespace,
        format_version=format_version,
        issued_at=current,
        expires_at=expires_at,
        payload=payload,
    )
    envelope = {
        "v": ENVELOPE_VERSION,
        "sid": sid,
        "ns": namespace,
        "fv": format_version,
        "iat": current,
        "exp": expires_at,
        "kid": key.kid,
        "payload": payload,
        "mac": _mac(key.secret, mac_input),
    }
    return _ENCODER.encode(envelope)


def open_envelope(
    *,
    record: bytes,
    expected_sid: str,
    expected_namespace: str,
    expected_format_version: int,
    keyring: KeyRing,
    allow_retired: bool = False,
    now: Optional[int] = None,
) -> bytes:
    """Verify an envelope and return the inner payload bytes.

    Raises an :class:`IntegrityError` subclass on any failure.
    """
    current = int(time.time()) if now is None else now
    try:
        envelope = _DECODER.decode(record)
    except msgspec.DecodeError as exc:
        raise TamperError("envelope is not decodable") from exc

    required = {"v", "sid", "ns", "fv", "iat", "exp", "kid", "payload", "mac"}
    if not isinstance(envelope, dict) or not required.issubset(envelope):
        raise TamperError("envelope missing required fields")
    if envelope["v"] != ENVELOPE_VERSION:
        raise ContextMismatchError(
            f"envelope version {envelope['v']!r} != {ENVELOPE_VERSION}"
        )

    key = keyring.verifier(envelope["kid"], allow_retired=allow_retired)

    mac_input = _mac_input(
        sid=envelope["sid"],
        namespace=envelope["ns"],
        format_version=envelope["fv"],
        issued_at=envelope["iat"],
        expires_at=envelope["exp"],
        payload=envelope["payload"],
    )
    expected_mac = _mac(key.secret, mac_input)
    if not hmac.compare_digest(expected_mac, envelope["mac"]):
        raise TamperError("HMAC mismatch")

    # context binding is checked *after* the MAC: an attacker cannot forge
    # envelopes for another sid/namespace/version without the key
    if envelope["sid"] != expected_sid:
        raise ContextMismatchError(
            f"sid mismatch: record belongs to {envelope['sid']!r},"
            f" requested {expected_sid!r}"
        )
    if envelope["ns"] != expected_namespace:
        raise ContextMismatchError(
            f"namespace mismatch: {envelope["ns"]!r} != {expected_namespace!r}"
        )
    if envelope["fv"] != expected_format_version:
        raise ContextMismatchError(
            f"format version mismatch: {envelope['fv']} != {expected_format_version}"
        )

    if envelope["exp"] is not None and current >= envelope["exp"]:
        raise ExpiredError(f"record expired at {envelope['exp']} (now {current})")

    return envelope["payload"]
