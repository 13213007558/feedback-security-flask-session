"""Storage wrapper that seals and verifies every session record."""

from __future__ import annotations

from datetime import timedelta as TimeDelta
from typing import Optional

import msgspec

from fake_storage import FakeStorage, FakeStorageSessionInterface
from integrity import (
    ContextMismatchError,
    IntegrityError,
    KeyRing,
    open_envelope,
    seal,
)


class ProtectedStorage:
    """Drop-in wrapper around :class:`FakeStorage` adding the MAC envelope."""

    def __init__(
        self,
        inner: FakeStorage,
        keyring: KeyRing,
        namespace: str,
        format_version: int,
    ):
        self.inner = inner
        self.keyring = keyring
        self.namespace = namespace
        self.format_version = format_version

    def put(self, *, sid: str, store_id: str, data: dict, ttl_seconds: int) -> None:
        payload = msgspec.msgpack.encode(data)
        record = seal(
            sid=sid,
            namespace=self.namespace,
            format_version=self.format_version,
            payload=payload,
            keyring=self.keyring,
            ttl_seconds=ttl_seconds,
        )
        self.inner.raw_set(store_id, record)

    def get(self, *, sid: str, store_id: str) -> Optional[dict]:
        record = self.inner.raw_get(store_id)
        if record is None:
            return None
        payload = open_envelope(
            record=record,
            expected_sid=sid,
            expected_namespace=self.namespace,
            expected_format_version=self.format_version,
            keyring=self.keyring,
        )
        return msgspec.msgpack.decode(payload)


class ProtectedSessionInterface(FakeStorageSessionInterface):
    """Same read/write path as the real interface, but storage is protected."""

    def __init__(self, app, storage: FakeStorage, protected: ProtectedStorage, **kwargs):
        self.protected = protected
        super().__init__(app, storage=storage, **kwargs)

    def _retrieve_session_data(self, store_id: str) -> Optional[dict]:
        sid = store_id[len(self.key_prefix):]
        try:
            return self.protected.get(sid=sid, store_id=store_id)
        except IntegrityError as exc:
            self.app.logger.warning("rejected session record %s: %s", store_id, exc)
            # treat a tampered record like a missing one: start a fresh session
            return None

    def _upsert_session(
        self,
        session_lifetime: TimeDelta,
        session,
        store_id: str,
    ) -> None:
        ttl_seconds = int(session_lifetime.total_seconds())
        self.protected.put(
            sid=session.sid,
            store_id=store_id,
            data=dict(session),
            ttl_seconds=ttl_seconds,
        )
