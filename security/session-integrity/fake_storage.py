"""In-memory fake of a server-side session storage backend.

It mimics the real backends (redis / cachelib / sqlalchemy ...): the
interface stores *only* the serialized session dict under a key of the form
``"<prefix><sid>"``. Nothing about the sid, the application or the payload
format is authenticated inside the stored value.
"""

from datetime import timedelta as TimeDelta
from typing import Dict, Optional

from flask_session.base import ServerSideSession, ServerSideSessionInterface
from flask_session._utils import total_seconds


class FakeStorage:
    """A dict-backed stand-in for Redis / a SQL table / a file cache."""

    def __init__(self) -> None:
        self.records: Dict[str, bytes] = {}
        self.ttl: Dict[str, int] = {}

    # raw access, intentionally available to "an attacker who can read storage"
    def raw_get(self, key: str) -> Optional[bytes]:
        return self.records.get(key)

    def raw_set(self, key: str, value: bytes) -> None:
        self.records[key] = value

    def raw_delete(self, key: str) -> None:
        self.records.pop(key, None)
        self.ttl.pop(key, None)


class FakeStorageSessionInterface(ServerSideSessionInterface):
    session_class = ServerSideSession
    ttl = True

    def __init__(self, app, storage: FakeStorage, **kwargs):
        self.storage = storage
        super().__init__(app, **kwargs)

    def _retrieve_session_data(self, store_id: str) -> Optional[dict]:
        serialized = self.storage.raw_get(store_id)
        if serialized is None:
            return None
        return self.serializer.loads(serialized)

    def _delete_session(self, store_id: str) -> None:
        self.storage.raw_delete(store_id)

    def _upsert_session(
        self,
        session_lifetime: TimeDelta,
        session: ServerSideSession,
        store_id: str,
    ) -> None:
        serialized = self.serializer.dumps(dict(session))
        self.storage.raw_set(store_id, serialized)
        self.storage.ttl[store_id] = total_seconds(session_lifetime)
