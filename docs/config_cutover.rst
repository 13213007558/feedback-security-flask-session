.. currentmodule:: flask_session

Storage migration (cutover protocol)
====================================

When session storage moves from an old service (the **legacy backend**) to a
new service (the **new backend**), the transition must keep every session
readable without ever allowing two services to write the same session at
once. The ``cutover`` session type implements a recoverable protocol built on
two durable facts stored in the new backend:

* a **phase marker** describing where the whole deployment is in the cutover;
* a per-session **authority record** naming the single backend that owns that
  session.

Dual writes are deliberately never used. The fact that both backends accepted
a write proves nothing about which one is authoritative; authority is always
the atomically claimed authority record instead.

Backends only need the small ``cachelib``-style interface (``get``, ``set``
with ``timeout``, an atomic ``add`` that returns ``False`` when the key
exists, and ``delete``). Two in-memory ``cachelib.simple.SimpleCache``
instances are enough to exercise the full protocol.

.. code-block:: python

    from cachelib.simple import SimpleCache
    from flask import Flask
    from flask_session import Session

    app = Flask(__name__)
    app.config.update(
        SESSION_TYPE="cutover",
        SESSION_CUTOVER_NEW=SimpleCache(),
        SESSION_CUTOVER_LEGACY=SimpleCache(),
        SESSION_CUTOVER_PHASE="cutover",
        SESSION_CUTOVER_IDENTITY_KEYS=("_user_id",),
    )
    Session(app)

Phases
------

The phase marker is stored in the new backend under
``SESSION_CUTOVER_PHASE_KEY`` and survives process restarts. Phase moves are
forward-only via :meth:`~flask_session.migration.CutoverSessionInterface.set_phase`.

``legacy``
    The old service is the sole owner. Sessions are read and written only on
    the legacy backend; the new backend is never touched.

``cutover`` (default)
    Reads use the **new backend first with a legacy fallback**. Un-migrated
    sessions keep taking ordinary, non-identity writes on the legacy backend,
    so no speculative dual ownership is created. A session migrates exactly
    once, on its first identity-changing write.

``new_only``
    The old service is retired. Legacy records are inert history: they are
    never read into a session and never written. Every write is claimed and
    stored in the new backend.

Read fallback order
-------------------

For every request the read order is fixed and side-effect free:

1. Read the authority record from the new backend. A ``tombstoned`` record
   always wins and yields an empty, anonymous session.
2. Read the session data from the new backend.
3. If absent and the phase still permits it (``legacy`` or ``cutover``), fall
   back to the legacy backend. In ``new_only`` no fallback happens.

A read never migrates, repairs, or writes anything. If a migration crashed
after claiming authority but before writing data, the legacy fallback keeps
serving the session until the next write resumes the migration.

Migration confirmation and invalidation order
---------------------------------------------

Migration is triggered by an identity-changing write (a change to one of
``SESSION_CUTOVER_IDENTITY_KEYS``). The ordering is strict and each step is
idempotent, so a crash at any point is recovered on the next request:

1. **Claim authority** with an atomic ``add`` on the authority record. If the
   claim cannot be completed, the identity change is refused rather than
   guessed.
2. **Read the legacy snapshot** so an interrupted migration cannot lose data.
3. **Write the data and the ``migrated`` authority record to the new
   backend.**
4. **Only then invalidate the legacy record** (delete it). There is no window
   in which the session exists in neither backend.

After migration the new backend is the single writer forever; a later write
to the legacy backend (for example from an old process that was never
retired) is fenced by the authority record and ignored by readers.

Failing closed on identity changes
----------------------------------

Identity is security-sensitive. When authority cannot be confirmed — the new
backend cannot claim, the phase marker is unreadable, or the session is
tombstoned — an identity-changing write raises
:class:`~flask_session.migration.AuthorityUnconfirmed`. The interface maps
this to a ``409 Conflict`` response carrying ``reauthenticate: true`` and
leaves every stored record untouched; ordinary, non-identity traffic may
still fall back to the legacy backend. A general protocol failure that
prevents any safe write maps to ``503 Service Unavailable`` via
:class:`~flask_session.migration.CutoverError`. Use
:func:`~flask_session.migration.register_cutover_error_handlers` if you also
raise these exceptions outside the response path.

Logout and tombstones
---------------------

Logout writes a ``tombstoned`` authority record first, deletes the new-backend
data, and invalidates the legacy record last. The tombstone outlives the data
and ensures that a late legacy write cannot resurrect an authenticated
session. If the tombstone itself cannot be persisted, logout fails closed and
the legacy record is deliberately left in place rather than deleted without
an authoritative fence.

Configuration
-------------

``SESSION_CUTOVER_NEW``
    The target backend instance. Required.

``SESSION_CUTOVER_LEGACY``
    The old backend instance, kept readable during the transition. Required.

``SESSION_CUTOVER_PHASE``
    Initial phase (``"legacy"``, ``"cutover"`` or ``"new_only"``) used until
    the durable phase marker is read. Defaults to ``"cutover"``.

``SESSION_CUTOVER_PHASE_KEY``
    Key of the durable phase marker. Defaults to ``"session_cutover:phase"``.

``SESSION_CUTOVER_IDENTITY_KEYS``
    Session keys whose add/remove/change counts as an identity change
    requiring confirmed authority. Defaults to ``("_user_id", "user_id")``.

``SESSION_CUTOVER_TOMBSTONE_TIMEOUT``
    Tombstone lifetime in seconds. Defaults to the permanent session
    lifetime.
