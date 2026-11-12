Batched cleanup contract for non-TTL backends
----------------------------------------------

.. module:: flask_session.cleanup

Storage engines without native time-to-live (TTL) support must remove expired
sessions themselves. A naive bulk ``DELETE ... WHERE expiry <= now()`` is
unsafe when cleanup runs concurrently with request traffic:

* a session can be **legitimately renewed** after the cleanup transaction
  observed it as expired, so an unconditional delete can remove a live record;
* a delayed **stale replica** of a record (for example one whose permissions
  were narrowed and re-saved) can overwrite the newer copy if writes are not
  fenced;
* an unbounded scan can hold locks or memory for too long and a crash halfway
  through leaves no way to resume.

The :mod:`flask_session.cleanup` package defines a small contract that removes
these hazards. :class:`~flask_session.cleanup.memory.InMemorySessionStore` is a
dependency-free reference implementation that real backends can port, and
:func:`~flask_session.cleanup.runner.run_cleanup` drives any conforming store.

Contract rules
~~~~~~~~~~~~~~

1. **Metadata-only scans.** A scan returns store ids and expiry timestamps
   only. Session payloads are never read, deserialized, returned or logged by
   cleanup code.
2. **Bounded, resumable scans.** Each scan returns at most ``batch_size``
   candidates plus an opaque keyset cursor. A sweep interrupted at any batch is
   continued with :func:`~flask_session.cleanup.runner.resume_cleanup` using
   the returned cursor.
3. **Conditional deletion.**
   :meth:`~flask_session.cleanup.contract.BatchCleanupStore.delete_session_if_expiry_matches`
   is an atomic compare-and-delete: the row is removed only when its expiry
   still equals the expiry observed by the scan and is still due. The boolean
   result distinguishes an actual deletion from a renewal or an already
   removed row.
4. **Monotonic, fenced writes.** Renewal upserts are atomic per key and can
   only move the expiry forward. The reference store raises
   :class:`~flask_session.cleanup.memory.StaleWriteError` on a backwards
   expiry, so an older, permission-broader copy cannot resurface.
5. **At-least-once delivery.** Resuming may re-observe a candidate; conditional
   deletion makes the repeated attempt idempotent.
6. **Count-only observability.** Progress and summary log lines contain
   aggregate integers (``scanned``, ``deleted``, ``skipped``, ``batches``)
   only. Store ids, cursors and session values are never logged.
7. **Fail closed.** A backend missing a required primitive raises
   :class:`~flask_session.cleanup.contract.UnsafeCleanupError` via
   :func:`~flask_session.cleanup.capabilities.ensure_cleanup_supported` rather
   than silently running an unsafe sweep.

Running a sweep
~~~~~~~~~~~~~~~

.. code-block:: python

    from flask_session.cleanup import (
        CleanupConfig,
        InMemorySessionStore,
        run_cleanup,
    )

    store = InMemorySessionStore()
    result = run_cleanup(store, CleanupConfig(batch_size=500, max_batches=20))
    print(result.as_counts())  # counts only, never session data

    if result.interrupted:
        # continue later, exactly where this sweep stopped
        result = resume_cleanup(store, result.resume_cursor)

Interruption is also available cooperatively through ``should_interrupt``,
which the runner checks once per batch so a graceful shutdown never loses the
resume position.

Backend capability audit
~~~~~~~~~~~~~~~~~~~~~~~~

:func:`~flask_session.cleanup.capabilities.assess_backend` records which
bundled backends may enable the guarantee:

* ``redis``, ``memcached``, ``filesystem``, ``cachelib``, ``mongodb`` and
  ``dynamodb`` provide native TTL. Manual cleanup is neither required nor
  permitted; the TTL mechanism itself is the expiry guarantee.
* ``sqlalchemy`` and ``postgresql`` have no native TTL. The relational engines
  support the required primitives (indexed range scan, single-row conditional
  ``DELETE``, atomic upsert, expiry-only projection), but the shipped adapters
  currently only expose an unbounded bulk delete and therefore fail the
  ``bounded_scan`` and ``conditional_delete`` checks. They must keep the
  guarantee disabled - :class:`UnsafeCleanupError` if enabled - until an
  adapter implementing :class:`~flask_session.cleanup.contract.BatchCleanupStore`
  is added.

Porting to a relational backend
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The two operations a relational adapter must provide map directly onto SQL.
The scan is a keyset range over the indexed expiry column, selecting the key
and expiry only, and the delete is a single-row compare-and-delete:

.. code-block:: sql

    SELECT session_id, expiry
    FROM sessions
    WHERE expiry <= :now AND session_id > :cursor
    ORDER BY session_id
    LIMIT :batch_size;

    DELETE FROM sessions
    WHERE session_id = :session_id AND expiry = :expected_expiry AND expiry <= :now;

The row count of the second statement is the conditional-delete boolean. The
existing upsert already updates the expiry atomically per key, satisfying the
monotonic-write requirement as long as renewal paths never write an older
expiry.
