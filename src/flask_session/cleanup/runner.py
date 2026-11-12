"""Drives a :class:`~flask_session.cleanup.contract.BatchCleanupStore`.

The runner interleaves bounded metadata scans with conditional deletes so that
renewals racing a sweep can never remove a live record.  It reports integer
counters only; no store id, cursor or session value is ever logged.
"""

import logging
from datetime import datetime, timezone
from typing import Callable, Optional

from .contract import (
    BatchCleanupStore,
    CleanupConfig,
    CleanupResult,
    UnsafeCleanupError,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def require_batch_cleanup_store(store: object) -> BatchCleanupStore:
    """Fail closed when ``store`` cannot honor the cleanup guarantee."""
    if isinstance(store, BatchCleanupStore):
        return store
    raise UnsafeCleanupError(
        "Backend does not implement the BatchCleanupStore contract; refusing "
        "to run a sweep that cannot guarantee conditional, value-isolated cleanup."
    )


def _sweep(
    store: BatchCleanupStore,
    config: CleanupConfig,
    reference_time: datetime,
    log: logging.Logger,
    start_cursor: Optional[str],
    should_interrupt: Optional[Callable[[], bool]],
) -> CleanupResult:
    result = CleanupResult()
    cursor: Optional[str] = start_cursor

    while True:
        if should_interrupt is not None and should_interrupt():
            result.interrupted = True
            result.resume_cursor = cursor
            log.warning(
                "session cleanup interrupted after %d batch(es); resume cursor retained",
                result.batches,
            )
            return result

        page = store.scan_expired_sessions(
            now=reference_time,
            limit=config.batch_size,
            cursor=cursor,
        )
        result.batches += 1
        result.scanned += len(page.candidates)

        for candidate in page.candidates:
            deleted = store.delete_session_if_expiry_matches(
                candidate.store_id,
                expected_expiry=candidate.expiry,
                now=reference_time,
            )
            if deleted:
                result.deleted += 1
            else:
                # Renewed, already removed, or no longer due: leave untouched.
                result.skipped += 1

        log.info(
            "session cleanup batch %d: scanned=%d deleted=%d skipped=%d",
            result.batches,
            len(page.candidates),
            result.deleted,
            result.skipped,
        )

        if page.next_cursor is None:
            result.resume_cursor = None
            log.info(
                "session cleanup complete: scanned=%d deleted=%d skipped=%d batches=%d",
                result.scanned,
                result.deleted,
                result.skipped,
                result.batches,
            )
            return result

        cursor = page.next_cursor

        if config.max_batches is not None and result.batches >= config.max_batches:
            result.interrupted = True
            result.resume_cursor = cursor
            log.warning(
                "session cleanup reached max_batches=%d; resume cursor retained",
                config.max_batches,
            )
            return result


def run_cleanup(
    store: object,
    config: Optional[CleanupConfig] = None,
    *,
    now: Optional[datetime] = None,
    logger: Optional[logging.Logger] = None,
    should_interrupt: Optional[Callable[[], bool]] = None,
) -> CleanupResult:
    """Run one bounded cleanup sweep from the beginning of the key range.

    :param store: Object implementing the structural
        :class:`BatchCleanupStore` protocol.
    :param config: Batch sizing.  Defaults to :class:`CleanupConfig` defaults.
    :param now: Overridable reference time (mainly for tests).
    :param logger: Receives count-only progress and summary lines.
    :param should_interrupt: Optional zero-argument callable checked once per
        batch; when it returns ``True`` the sweep stops and the current cursor
        is returned for resume.
    :raises UnsafeCleanupError: if ``store`` lacks contract operations.
    """
    cleanup_store = require_batch_cleanup_store(store)
    return _sweep(
        store=cleanup_store,
        config=config or CleanupConfig(),
        reference_time=now or _utcnow(),
        log=logger or logging.getLogger(__name__),
        start_cursor=None,
        should_interrupt=should_interrupt,
    )


def resume_cleanup(
    store: object,
    resume_cursor: Optional[str],
    config: Optional[CleanupConfig] = None,
    *,
    now: Optional[datetime] = None,
    logger: Optional[logging.Logger] = None,
    should_interrupt: Optional[Callable[[], bool]] = None,
) -> CleanupResult:
    """Continue a previously interrupted sweep from ``resume_cursor``.

    At-least-once delivery means records adjacent to the cursor may be
    re-observed; conditional deletion keeps the resumed sweep idempotent.
    """
    cleanup_store = require_batch_cleanup_store(store)
    return _sweep(
        store=cleanup_store,
        config=config or CleanupConfig(),
        reference_time=now or _utcnow(),
        log=logger or logging.getLogger(__name__),
        start_cursor=resume_cursor,
        should_interrupt=should_interrupt,
    )
