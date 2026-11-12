"""Batched, conditional cleanup for backends without native TTL.

Public surface:

- :class:`CleanupConfig`, :class:`CleanupResult`,
  :class:`ExpiredSessionCandidate`, :class:`ScanPage` -- the data contract.
- :class:`BatchCleanupStore`, :class:`AbstractBatchCleanupStore`,
  :class:`StoreCapabilities` -- operations and capability checks.
- :class:`InMemorySessionStore` -- dependency-free reference implementation.
- :func:`run_cleanup`, :func:`resume_cleanup` -- bounded sweep runners.
- :func:`assess_backend`, :func:`ensure_cleanup_supported` -- fail-closed gate.
- :class:`UnsafeCleanupError`, :class:`StaleWriteError`.
"""

from .capabilities import all_assessments, assess_backend, ensure_cleanup_supported
from .contract import (
    AbstractBatchCleanupStore,
    BackendCleanupAssessment,
    BatchCleanupStore,
    CleanupConfig,
    CleanupResult,
    ExpiredSessionCandidate,
    ScanPage,
    StoreCapabilities,
    UnsafeCleanupError,
)
from .memory import InMemorySessionStore, StaleWriteError
from .runner import require_batch_cleanup_store, resume_cleanup, run_cleanup

__all__ = [
    "AbstractBatchCleanupStore",
    "BackendCleanupAssessment",
    "BatchCleanupStore",
    "CleanupConfig",
    "CleanupResult",
    "ExpiredSessionCandidate",
    "ScanPage",
    "StoreCapabilities",
    "UnsafeCleanupError",
    "InMemorySessionStore",
    "StaleWriteError",
    "run_cleanup",
    "resume_cleanup",
    "require_batch_cleanup_store",
    "assess_backend",
    "all_assessments",
    "ensure_cleanup_supported",
]
