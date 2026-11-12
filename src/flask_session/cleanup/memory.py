"""In-memory reference implementation of the batch cleanup contract.

This is intentionally dependency-free and written to be copied or adapted by
real backends: every rule in :mod:`flask_session.cleanup.contract` has a
concrete, testable realization here.  It is suitable for tests, development and
single-process deployments; it is not persistent.

The store keeps session payloads but never returns them from a scan.  Writes
are fenced by expiry: an upsert that would move a record's expiry backwards is
rejected, which is what stops a permission-narrowed stale replica from
reappearing on top of a newer record.
"""

import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from .contract import (
    AbstractBatchCleanupStore,
    ExpiredSessionCandidate,
    ScanPage,
    _utc,
)


class StaleWriteError(ValueError):
    """Raised when an upsert would regress a record's expiry fence."""


@dataclass(frozen=True)
class _MemoryRecord:
    expiry: datetime
    value: object


class InMemorySessionStore(AbstractBatchCleanupStore):
    """Thread-safe, cursor-paginated, conditionally-deleting session store."""

    def __init__(self) -> None:
        self._records: dict = {}
        self._lock = threading.RLock()

    def upsert_session(self, store_id: str, value: object, expiry: datetime) -> None:
        """Create or renew a session.

        Renewals must move the expiry strictly forward.  A write carrying an
        older expiry (for example a delayed message for a record whose rights
        were since narrowed and re-saved with a later fence) is rejected, so a
        stale copy can never replace the current one.
        """
        expiry = _utc(expiry)
        with self._lock:
            current = self._records.get(store_id)
            if current is not None and expiry < current.expiry:
                raise StaleWriteError(
                    "Refusing to overwrite a newer record with an older expiry"
                )
            self._records[store_id] = _MemoryRecord(expiry=expiry, value=value)

    def renew_session(self, store_id: str, expiry: datetime) -> None:
        """Move only the expiry fence forward, preserving the stored payload."""
        expiry = _utc(expiry)
        with self._lock:
            current = self._records.get(store_id)
            if current is None:
                raise KeyError(store_id)
            if expiry < current.expiry:
                raise StaleWriteError(
                    "Refusing to renew a record with an older expiry"
                )
            self._records[store_id] = _MemoryRecord(
                expiry=expiry, value=current.value
            )

    def get_session(self, store_id: str, *, now: datetime) -> Optional[object]:
        """Read a live session payload; expired rows read as absent."""
        now = _utc(now)
        with self._lock:
            record = self._records.get(store_id)
            if record is None or record.expiry <= now:
                return None
            return record.value

    def delete_session(self, store_id: str) -> bool:
        with self._lock:
            existed = store_id in self._records
            self._records.pop(store_id, None)
            return existed

    def scan_expired_sessions(
        self,
        *,
        now: datetime,
        limit: int,
        cursor: Optional[str],
    ) -> ScanPage:
        if limit <= 0:
            raise ValueError("limit must be a positive integer")
        now = _utc(now)
        with self._lock:
            # Stable keyset: sort by store id, resume strictly after the cursor.
            ordered_ids = sorted(self._records)
            start = 0
            if cursor is not None:
                start = self._cursor_position(ordered_ids, cursor)
            page_ids = []
            for store_id in ordered_ids[start:]:
                if self._records[store_id].expiry <= now:
                    page_ids.append(store_id)
                    if len(page_ids) == limit:
                        break
            candidates = [
                ExpiredSessionCandidate(
                    store_id=store_id,
                    expiry=self._records[store_id].expiry,
                )
                for store_id in page_ids
            ]
            next_cursor = page_ids[-1] if page_ids else None
            # Exhausted when no further id exists after the last delivered one.
            if next_cursor is not None:
                last_index = ordered_ids.index(next_cursor)
                if last_index == len(ordered_ids) - 1:
                    next_cursor = None
            return ScanPage(candidates=candidates, next_cursor=next_cursor)

    def delete_session_if_expiry_matches(
        self,
        store_id: str,
        *,
        expected_expiry: datetime,
        now: datetime,
    ) -> bool:
        expected_expiry = _utc(expected_expiry)
        now = _utc(now)
        with self._lock:
            record = self._records.get(store_id)
            if record is None:
                return False
            if record.expiry != expected_expiry:
                # Renewed between scan and delete; the live record is preserved.
                return False
            if record.expiry > now:
                # Clock edge: no longer due.  Do not delete.
                return False
            del self._records[store_id]
            return True

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._records)

    @staticmethod
    def _cursor_position(ordered_ids, cursor: str) -> int:
        # Keyset resume: only ids strictly greater than the cursor are visited.
        for index, store_id in enumerate(ordered_ids):
            if store_id > cursor:
                return index
        return len(ordered_ids)
