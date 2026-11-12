"""Batched expired-session cleanup contract.

Backends without a native time-to-live (TTL) mechanism cannot rely on the
storage engine to remove expired sessions.  This module defines the contract
that such a backend must implement so that expired sessions can be reaped in
bounded batches without ever deleting a record that has been legitimately
renewed and without allowing a stale (for example permission-narrowed) copy of
a record to resurface.

Contract rules
--------------

1. **Metadata-only scans.** A scan returns store ids and expiry timestamps,
   never session payloads.  Session values must not be deserialized, copied or
   logged in order to drive cleanup.
2. **Bounded, resumable scans.** Every scan call returns at most ``limit``
   candidates and an opaque cursor.  A caller resumes an interrupted sweep by
   handing the last cursor back; cursors use stable keyset ordering so inserts
   and renewals cannot skip or duplicate work beyond harmless re-delivery.
3. **Conditional deletion.** A delete is an atomic compare-and-delete keyed on
   the expiry observed during the scan.  It returns whether a row was actually
   removed.  If the record was renewed (its expiry fence moved) between the
   scan and the delete, the condition no longer matches and the live record is
   preserved.
4. **Monotonic, fenced writes.** Renewal upserts are atomic per key and must
   never move the expiry/fence backwards, so a delayed stale replica cannot
   overwrite a newer record with an older copy.
5. **At-least-once delivery.** Resuming after an interruption may re-observe an
   already deleted candidate; the conditional delete makes this idempotent.
6. **Count-only observability.** Cleanup emits integer counters only.  Store
   ids, cursors and session values never cross the logging boundary.
7. **Fail closed.** A backend that cannot satisfy any of the capabilities
   above must raise :class:`UnsafeCleanupError` instead of silently running an
   unsafe sweep.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Protocol, Sequence, runtime_checkable


def _utc(value: datetime) -> datetime:
    """Normalize a timestamp to timezone-aware UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class ExpiredSessionCandidate:
    """A scan hit for cleanup.

    Deliberately carries no slot for session data: cleanup decisions are made
    from the store id and the expiry fence only, so a payload cannot leak into
    cleanup code paths or log output.
    """

    store_id: str
    expiry: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "expiry", _utc(self.expiry))


@dataclass(frozen=True)
class ScanPage:
    """One bounded page of cleanup candidates."""

    candidates: Sequence[ExpiredSessionCandidate]
    next_cursor: Optional[str]


@dataclass(frozen=True)
class CleanupConfig:
    """Knobs for a single cleanup sweep.

    :param batch_size: Maximum number of candidates scanned per batch.
    :param max_batches: Maximum number of batches performed in this sweep.
        ``None`` means run until the scan is exhausted.  When the cap is hit
        the returned resume cursor allows a later sweep to continue.
    """

    batch_size: int = 500
    max_batches: Optional[int] = None

    def __post_init__(self) -> None:
        if self.batch_size <= 0:
            raise ValueError("batch_size must be a positive integer")
        if self.max_batches is not None and self.max_batches <= 0:
            raise ValueError("max_batches must be positive or None")


@dataclass
class CleanupResult:
    """Count-only outcome of a cleanup sweep.

    Holds aggregate integers and the opaque resume cursor.  It never holds
    session values or individual store ids.
    """

    scanned: int = 0
    deleted: int = 0
    skipped: int = 0
    batches: int = 0
    interrupted: bool = False
    resume_cursor: Optional[str] = None

    def as_counts(self) -> dict:
        return {
            "scanned": self.scanned,
            "deleted": self.deleted,
            "skipped": self.skipped,
            "batches": self.batches,
            "interrupted": self.interrupted,
        }


class UnsafeCleanupError(RuntimeError):
    """Raised when a backend cannot honor the batch cleanup guarantee.

    Raising (rather than degrading to an unsafe sweep) is part of the contract:
    callers must never believe expired data is safely reaped when the storage
    layer lacks a required capability.
    """


@runtime_checkable
class BatchCleanupStore(Protocol):
    """Storage operations a backend must expose for safe batched cleanup."""

    def scan_expired_sessions(
        self,
        *,
        now: datetime,
        limit: int,
        cursor: Optional[str],
    ) -> ScanPage:
        """Return at most ``limit`` records with ``expiry <= now``.

        Implementations order rows by a stable key and treat ``cursor`` as an
        opaque keyset position (``None`` starts from the beginning).  Session
        payloads must not be read or returned.
        """

    def delete_session_if_expiry_matches(
        self,
        store_id: str,
        *,
        expected_expiry: datetime,
        now: datetime,
    ) -> bool:
        """Atomically delete ``store_id`` when its expiry still matches.

        The delete only succeeds when the stored expiry equals
        ``expected_expiry`` *and* is still due (``expiry <= now``).  Returns
        ``True`` when a row was deleted, ``False`` when the record was renewed,
        already removed, or otherwise no longer matches the observed fence.
        """


class AbstractBatchCleanupStore(ABC):
    """Optional base class for backend cleanup adapters.

    Backends can subclass this to get static checking of the contract surface;
    the structural :class:`BatchCleanupStore` protocol is what the runner
    consumes.
    """

    @abstractmethod
    def scan_expired_sessions(
        self,
        *,
        now: datetime,
        limit: int,
        cursor: Optional[str],
    ) -> ScanPage:
        raise NotImplementedError()

    @abstractmethod
    def delete_session_if_expiry_matches(
        self,
        store_id: str,
        *,
        expected_expiry: datetime,
        now: datetime,
    ) -> bool:
        raise NotImplementedError()


@dataclass(frozen=True)
class StoreCapabilities:
    """Capability matrix used to audit concrete backends.

    :param bounded_scan: Keyset/range scan with a hard row limit and resumable
        cursor.
    :param conditional_delete: Atomic compare-and-delete that reports whether
        a row was removed.
    :param monotonic_writes: Per-key atomic upserts whose expiry/fence can only
        move forward, so stale replicas cannot resurrect old copies.
    :param value_isolated_scan: Expiry metadata can be scanned without reading
        or deserializing session payloads.
    """

    bounded_scan: bool
    conditional_delete: bool
    monotonic_writes: bool
    value_isolated_scan: bool

    def missing(self):
        return tuple(
            name
            for name, present in (
                ("bounded_scan", self.bounded_scan),
                ("conditional_delete", self.conditional_delete),
                ("monotonic_writes", self.monotonic_writes),
                ("value_isolated_scan", self.value_isolated_scan),
            )
            if not present
        )


@dataclass(frozen=True)
class BackendCleanupAssessment:
    """Audit verdict for one bundled backend."""

    backend: str
    native_ttl: bool
    capabilities: Optional[StoreCapabilities]
    reason: str

    @property
    def eligible(self) -> bool:
        return (
            not self.native_ttl
            and self.capabilities is not None
            and not self.capabilities.missing()
        )
