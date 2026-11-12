"""Tests for the session-record integrity envelope."""

import sys
from pathlib import Path

import msgspec
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from integrity import (  # noqa: E402
    ContextMismatchError,
    ExpiredError,
    KeyRetiredError,
    KeyRing,
    SigningKey,
    TamperError,
    open_envelope,
    seal,
)

NS = "billing-app"
FV = 1
SID_A = "sid-alice"
SID_B = "sid-bob"
PAYLOAD = msgspec.msgpack.encode({"user": "alice", "role": "user"})


def make_ring() -> KeyRing:
    return KeyRing(SigningKey(kid="k1", secret=b"primary-secret"))


def seal_one(ring, sid=SID_A, namespace=NS, format_version=FV, ttl=3600, now=10000):
    return seal(
        sid=sid,
        namespace=namespace,
        format_version=format_version,
        payload=PAYLOAD,
        keyring=ring,
        ttl_seconds=ttl,
        now=now,
    )


def test_round_trip_returns_payload():
    ring = make_ring()
    record = seal_one(ring)
    out = open_envelope(
        record=record,
        expected_sid=SID_A,
        expected_namespace=NS,
        expected_format_version=FV,
        keyring=ring,
        now=10100,
    )
    assert out == PAYLOAD


def test_payload_tamper_is_detected():
    ring = make_ring()
    record = seal_one(ring)
    decoded = msgspec.msgpack.decode(record)
    decoded["payload"] = msgspec.msgpack.encode({"role": "admin"})
    tampered = msgspec.msgpack.encode(decoded)
    with pytest.raises(TamperError):
        open_envelope(
            record=tampered,
            expected_sid=SID_A,
            expected_namespace=NS,
            expected_format_version=FV,
            keyring=ring,
            now=10100,
        )


def test_mac_field_tamper_is_detected():
    ring = make_ring()
    record = seal_one(ring)
    decoded = msgspec.msgpack.decode(record)
    decoded["mac"] = b"\x00" * len(decoded["mac"])
    with pytest.raises(TamperError):
        open_envelope(
            record=msgspec.msgpack.encode(decoded),
            expected_sid=SID_A,
            expected_namespace=NS,
            expected_format_version=FV,
            keyring=ring,
            now=10100,
        )


def test_record_swap_between_sids_is_detected():
    # attacker moves alice's valid record under bob's storage key
    ring = make_ring()
    record = seal_one(ring, sid=SID_A)
    with pytest.raises(ContextMismatchError, match="sid mismatch"):
        open_envelope(
            record=record,
            expected_sid=SID_B,
            expected_namespace=NS,
            expected_format_version=FV,
            keyring=ring,
            now=10100,
        )


def test_cross_namespace_record_is_rejected():
    ring = make_ring()
    record = seal_one(ring, namespace="other-app")
    with pytest.raises(ContextMismatchError, match="namespace mismatch"):
        open_envelope(
            record=record,
            expected_sid=SID_A,
            expected_namespace=NS,
            expected_format_version=FV,
            keyring=ring,
            now=10100,
        )


def test_format_version_mismatch_is_rejected():
    ring = make_ring()
    record = seal_one(ring, format_version=2)
    with pytest.raises(ContextMismatchError, match="format version mismatch"):
        open_envelope(
            record=record,
            expected_sid=SID_A,
            expected_namespace=NS,
            expected_format_version=FV,
            keyring=ring,
            now=10100,
        )


def test_expired_record_is_rejected():
    ring = make_ring()
    record = seal_one(ring, ttl=3600, now=10000)
    with pytest.raises(ExpiredError):
        open_envelope(
            record=record,
            expected_sid=SID_A,
            expected_namespace=NS,
            expected_format_version=FV,
            keyring=ring,
            now=10000 + 3600,
        )


def test_record_without_expiry_does_not_expire():
    ring = make_ring()
    record = seal_one(ring, ttl=None)
    out = open_envelope(
        record=record,
        expected_sid=SID_A,
        expected_namespace=NS,
        expected_format_version=FV,
        keyring=ring,
        now=10**9,
    )
    assert out == PAYLOAD


def test_unknown_kid_is_rejected():
    ring = make_ring()
    record = seal_one(ring)
    other_ring = KeyRing(SigningKey(kid="k9", secret=b"different-secret"))
    with pytest.raises(KeyRetiredError):
        open_envelope(
            record=record,
            expected_sid=SID_A,
            expected_namespace=NS,
            expected_format_version=FV,
            keyring=other_ring,
            now=10100,
        )


def test_retired_verifier_key_is_refused_by_default():
    retired = SigningKey(kid="k-old", secret=b"old-secret", retired=True)
    ring = KeyRing(
        SigningKey(kid="k-new", secret=b"new-secret"),
        keys={"k-old": retired},
    )
    old_ring = KeyRing(SigningKey(kid="k-old", secret=b"old-secret"))
    record = seal_one(old_ring)
    with pytest.raises(KeyRetiredError):
        open_envelope(
            record=record,
            expected_sid=SID_A,
            expected_namespace=NS,
            expected_format_version=FV,
            keyring=ring,
            now=10100,
        )


def test_retired_key_can_verify_legacy_records_during_grace_period():
    retired = SigningKey(kid="k-old", secret=b"old-secret", retired=True)
    ring = KeyRing(
        SigningKey(kid="k-new", secret=b"new-secret"),
        keys={"k-old": retired},
    )
    old_ring = KeyRing(SigningKey(kid="k-old", secret=b"old-secret"))
    record = seal_one(old_ring)
    out = open_envelope(
        record=record,
        expected_sid=SID_A,
        expected_namespace=NS,
        expected_format_version=FV,
        keyring=ring,
        allow_retired=True,
        now=10100,
    )
    assert out == PAYLOAD


def test_key_rotation_new_records_use_new_kid():
    ring = make_ring()
    ring.rotate(SigningKey(kid="k2", secret=b"rotated-secret"))
    record = seal_one(ring)
    assert msgspec.msgpack.decode(record)["kid"] == "k2"
    # records sealed before rotation still verify with the retained old key
    old_record = seal_one(make_ring())
    out = open_envelope(
        record=old_record,
        expected_sid=SID_A,
        expected_namespace=NS,
        expected_format_version=FV,
        keyring=ring,
        now=10100,
    )
    assert out == PAYLOAD


def test_cannot_sign_with_retired_signing_key():
    ring = KeyRing(SigningKey(kid="k1", secret=b"s"))
    ring.keys["k1"] = SigningKey(kid="k1", secret=b"s", retired=True)
    with pytest.raises(KeyRetiredError):
        seal_one(ring)
