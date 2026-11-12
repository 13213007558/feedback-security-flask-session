"""Exceptions backing the decidable retry contract.

The retry layer distinguishes three situations instead of treating every
raised exception the same:

* :class:`RetriableSessionError` - the failure happened *before* the state
  change was committed. Nothing was applied, so the same request can be
  replayed safely.
* :class:`AmbiguousSessionStateError` - the backend may have committed the
  write but the client never got a response (timeout, dropped connection).
  The result is unknown; the operation must not be silently retried or
  reported as failed/succeeded without evidence.
* every other exception - a definite, non-transient error that is never
  retried.
"""


class SessionStorageError(Exception):
    """Base class for storage errors the retry layer understands."""


class RetriableSessionError(SessionStorageError):
    """The change was not committed; retrying cannot apply it twice."""


class AmbiguousSessionStateError(SessionStorageError):
    """The write may have committed even though the client saw a failure.

    :param operation: ``"retrieve"``, ``"upsert"`` or ``"delete"``.
    :param store_id: The storage key whose final state is unknown.
    :param cause: The original driver exception, kept as ``__cause__``.
    """

    def __init__(self, operation: str, store_id: str, cause: BaseException):
        self.operation = operation
        self.store_id = store_id
        self.cause = cause
        super().__init__(
            f"Outcome of {operation} on {store_id!r} is unknown: {cause!r}. "
            "The backend may have committed the change; it is never retried "
            "without an idempotency guarantee, and never hidden behind an "
            "unbounded retry loop."
        )
