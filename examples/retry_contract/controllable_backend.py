"""A fully in-memory, fault-injectable session backend.

It has no external service dependency and lets a test/demo decide *where* a
failure happens relative to the state change:

* ``pre_commit``  -> the driver raises *before* the store is mutated, so the
  outcome is known to be "not applied" and safe to retry.
* ``post_commit`` -> the store is mutated first, then the driver raises a
  timeout, the exact shape of "backend finished the write but the client only
  sees a lost response". The outcome is genuinely ambiguous to the caller.

The interface classifies these driver-level errors into the retry contract
exceptions (:class:`RetriableSessionError` /
:class:`AmbiguousSessionStateError`); this is the pattern every real backend
must implement. Every call is counted and every observed store id is recorded
so the number of physical operations and the identity used by the next
request can be asserted deterministically.
"""

from datetime import timedelta as TimeDelta
from typing import Any, Dict, List, Optional

from flask import Flask

from flask_session.base import ServerSideSession, ServerSideSessionInterface
from flask_session.exceptions import (
    AmbiguousSessionStateError,
    RetriableSessionError,
)


class TransientStorageError(Exception):
    """Connection style failure raised *before* the commit point."""


class CommitTimeout(Exception):
    """Timeout raised *after* the commit point (result unknown)."""


class ControllableStore:
    """In-memory key/value store with scripted faults and a call journal."""

    def __init__(self) -> None:
        self._data: Dict[str, Any] = {}
        self.calls: List[str] = []
        # operation -> number of faults still to raise, and which kind
        self._faults: Dict[str, Dict[str, Any]] = {}

    def configure_fault(
        self, operation: str, times: int, kind: str = "pre_commit"
    ) -> None:
        assert operation in {"get", "set", "delete"}
        assert kind in {"pre_commit", "post_commit"}
        self._faults[operation] = {"times": times, "kind": kind}

    def reset_journal(self) -> None:
        self.calls = []

    def reset(self) -> None:
        self._data.clear()
        self.calls.clear()
        self._faults.clear()

    def _pre_commit_fault(self, operation: str) -> None:
        fault = self._faults.get(operation)
        if fault and fault["times"] > 0 and fault["kind"] == "pre_commit":
            fault["times"] -= 1
            raise TransientStorageError(f"{operation}: failed before commit")

    def _post_commit_fault(self, operation: str) -> None:
        fault = self._faults.get(operation)
        if fault and fault["times"] > 0 and fault["kind"] == "post_commit":
            fault["times"] -= 1
            raise CommitTimeout(f"{operation}: committed, response lost")

    # driver-level primitives used by the session interface ------------------

    def get(self, store_id: str) -> Any:
        self.calls.append(f"get({store_id})")
        self._pre_commit_fault("get")
        value = self._data.get(store_id)
        self._post_commit_fault("get")
        return value

    def set(self, store_id: str, value: Any) -> None:
        self.calls.append(f"set({store_id})")
        self._pre_commit_fault("set")
        # commit point: once this line runs the write is durable
        self._data[store_id] = value
        self._post_commit_fault("set")

    def delete(self, store_id: str) -> None:
        self.calls.append(f"delete({store_id})")
        self._pre_commit_fault("delete")
        # commit point
        self._data.pop(store_id, None)
        self._post_commit_fault("delete")

    def exists(self, store_id: str) -> bool:
        return store_id in self._data

    def snapshot_ids(self) -> List[str]:
        return sorted(self._data)


class ControllableSession(ServerSideSession):
    pass


class ControllableSessionInterface(ServerSideSessionInterface):
    """Session interface backed by :class:`ControllableStore`.

    Concrete methods intentionally carry no ``@retry_query`` of their own: the
    retry contract is inherited from :class:`ServerSideSessionInterface` once
    the decorator ordering is correct.
    """

    session_class = ControllableSession
    ttl = True

    def __init__(self, app: Flask, store: Optional[ControllableStore] = None):
        self.store = store or ControllableStore()
        super().__init__(app)

    def _retrieve_session_data_impl(self, store_id: str) -> Optional[dict]:
        try:
            value = self.store.get(store_id)
        except TransientStorageError as exc:
            raise RetriableSessionError(str(exc)) from exc
        except CommitTimeout as exc:
            raise AmbiguousSessionStateError("retrieve", store_id, exc) from exc
        return self.serializer.loads(value) if value else None

    def _delete_session_impl(self, store_id: str) -> None:
        try:
            self.store.delete(store_id)
        except TransientStorageError as exc:
            raise RetriableSessionError(str(exc)) from exc
        except CommitTimeout as exc:
            raise AmbiguousSessionStateError("delete", store_id, exc) from exc

    def _upsert_session_impl(
        self, session_lifetime: TimeDelta, session: ServerSideSession, store_id: str
    ) -> None:
        try:
            self.store.set(store_id, self.serializer.dumps(dict(session)))
        except TransientStorageError as exc:
            raise RetriableSessionError(str(exc)) from exc
        except CommitTimeout as exc:
            raise AmbiguousSessionStateError("upsert", store_id, exc) from exc
