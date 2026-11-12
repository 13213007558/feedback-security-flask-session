.. currentmodule:: flask_session

Retry contract for security state changes
=========================================

Session saves, deletes and identity rotation (:meth:`ServerSideSessionInterface.regenerate`)
are security-relevant state changes. A storage call can fail in two fundamentally
different places:

* **Before the commit point** - nothing was written. The outcome is known to be
  "not applied" and the same request can be replayed safely.
* **After the commit point** - the backend may have durably applied the change,
  but the client only sees a timeout or a dropped connection. The outcome is
  genuinely unknown. Retrying blindly can duplicate a write or resurrect a
  login that was supposed to be deleted.

The retry layer therefore never treats "an exception was raised" as "the change
did not happen".

The contract
------------

Backends classify every driver failure into one of three categories using
:mod:`flask_session.exceptions`:

.. list-table::
   :header-rows: 1
   :widths: 28 36 36

   * - Exception
     - Meaning
     - Retry behaviour
   * - :class:`~flask_session.exceptions.RetriableSessionError`
     - Failure happened before commit; storage is unchanged.
     - Retried up to ``max_attempts`` (default 3) with exponential backoff.
   * - :class:`~flask_session.exceptions.AmbiguousSessionStateError`
     - The write may have committed; the result cannot be determined.
     - Replayed only when the operation is provably idempotent; otherwise
       surfaced immediately. Never hidden behind infinite retries.
   * - Any other exception
     - Definite, non-transient error (constraint violation, programming error,
       serialization failure, ...).
     - Propagated on the first attempt, never retried.

Operation matrix
----------------

.. list-table::
   :header-rows: 1
   :widths: 20 22 30 28

   * - Operation
     - Idempotent?
     - Pre-commit failure
     - Post-commit (ambiguous) failure
   * - ``_retrieve_session_data`` (read)
     - Yes
     - Retry.
     - Retry (a read cannot change state).
   * - ``_delete_session`` (key-scoped delete)
     - Yes
     - Retry; deleting an absent key is a no-op.
     - Retry to converge, bounded; then surface
       :class:`~flask_session.exceptions.AmbiguousSessionStateError`.
   * - ``_upsert_session`` key-based SET / upsert
     - Yes
     - Retry.
     - Retry to converge, bounded; then surface ambiguity.
   * - ``_upsert_session`` INSERT-only
     - **No**
     - Retry.
     - Abort immediately with ambiguity; a retry risks a duplicate row.

Identity rotation and logout rules
----------------------------------

:meth:`ServerSideSessionInterface.regenerate` deletes the old session record
*before* a new session id is minted. If the deletion cannot be confirmed
(transient retries exhausted or an ambiguous result), the current sid is kept
and the exception propagates:

* a new cookie is never issued while the old authenticated record may still
  exist, which closes the session-fixation window;
* the next request continues with the original identity instead of silently
  losing or duplicating the session.

The same rule applies to logout and to saves in :meth:`ServerSideSessionInterface.save_session`:
storage is written first, and the cookie is only set or cleared once the
storage outcome is known. An ambiguous delete never tells the browser to drop
its cookie while the server record may still be valid (which would leave a
"logged out" user authenticated on the server), and an ambiguous upsert never
points a browser at a session whose save is unconfirmed. A deleted login is
never re-saved.

Backend implementation guide
----------------------------

Every backend implements the private ``_*_impl`` primitives; the
:class:`ServerSideSessionInterface` wraps each one once with the retry
contract. Do not add ``@retry_query`` to the concrete methods - decorating an
``abstractmethod`` is silently overridden by subclasses, and double decoration
multiplies the attempt count.

1. **Identify the commit point** of each primitive - the single line after
   which the change is durable (``SET``, ``DELETE``, ``commit()``,
   ``update_one(..., upsert=True)``, ...).
2. **Map driver exceptions relative to that point.** Failures raised before it
   that are connection/timeout class become
   :class:`~flask_session.exceptions.RetriableSessionError`; failures raised by
   or after the commit acknowledgement become
   :class:`~flask_session.exceptions.AmbiguousSessionStateError`. Everything
   else is re-raised unchanged.
3. **Roll back any open transaction** before translating the exception so a
   retried call starts from a clean state.
4. **Prefer idempotent writes.** Use key-based ``SET`` (Redis, Memcached,
   cachelib), ``UPDATE ... ON CONFLICT DO UPDATE`` (SQL) or conditional
   ``upsert`` (Mongo, DynamoDB). Reserve ``idempotent=False`` for INSERT-only
   designs that cannot converge on replay.
5. **Keep TTL/expiry deterministic across retries.** Compute the expiration
   once and reuse the same value, so a replay cannot extend or shorten the
   session lifetime.
6. **Do not swallow the cause.** Raise the contract exception with ``from exc``
   so the original driver error stays on ``__cause__`` and is logged.

Minimal example::

    from flask_session.exceptions import (
        AmbiguousSessionStateError,
        RetriableSessionError,
    )

    def _delete_session_impl(self, store_id):
        try:
            self.client.delete(store_id)          # commit point
        except ConnectionError as exc:            # driver-specific, pre-commit
            raise RetriableSessionError(str(exc)) from exc
        except TimeoutError as exc:               # ack lost after commit
            raise AmbiguousSessionStateError("delete", store_id, exc) from exc

A runnable, fault-injectable reference backend and a scenario script live under
``examples/retry_contract/``; the behaviour is pinned by
``tests/test_retry_contract.py``.
