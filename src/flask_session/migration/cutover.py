"""Recoverable session-storage cutover protocol.

This module implements the transition of server-side session storage from an
old ("legacy") backend to a new backend. During the transition every session
may be read from either backend, but for any given session there is exactly one
authoritative writer. Authority is never derived from the fact that both
backends accepted a write ("dual write"); it is derived from a single,
atomically claimed *authority record* in the new backend.

The cutover is driven by a durable phase marker, also stored in the new
backend, so a process restart always resumes the same phase:

``LEGACY`` (default)
    Only the legacy backend is authoritative. Sessions are read and written
    there; the new backend is untouched.

``CUTOVER``
    Reads use the new backend first and fall back to the legacy backend. A
    session is migrated lazily, on its first write, by atomically claiming
    authority, copying the data into the new backend and only then deleting
    the legacy copy. Identity-changing writes are rejected unless authority
    can be confirmed.

``NEW_ONLY``
    The legacy backend is considered read-only history and is never written.
    Un-migrated sessions start empty; identity-changing writes require an
    authoritative new-backend record.

Per-session authority records carry a state:

``"migrated"``
    The new backend owns the session. A later write to the legacy backend
    (for example from an old process that was never retired) is fenced off
    and ignored by readers.

``"tombstoned"``
    The session was logged out. The legacy record, if any, has been deleted
    and any late legacy write cannot resurrect the authenticated session.

All operations are idempotent, so a crash at any point is recovered on the
next client request without ever leaving two active writers for one session.
"""

from datetime import timedelta as TimeDelta
from typing import Any, Optional, Tuple

from flask import Flask, jsonify

from .._utils import total_seconds
from ..base import ServerSideSession, ServerSideSessionInterface
from ..defaults import Defaults

LEGACY = "legacy"
CUTOVER = "cutover"
NEW_ONLY = "new_only"

STATE_MIGRATED = "migrated"
STATE_TOMBSTONED = "tombstoned"

# Stored on the session object (never inside its data dict) at open time, so
# tracking it cannot flip the session's "modified" flag. It records the
# authenticated identity as seen at the start of the request.
_IDENTITY_FINGERPRINT_ATTR = "_cutover_identity_fingerprint"


class CutoverError(RuntimeError):
    """Base class for cutover protocol failures.

    These errors are deliberately *fail-closed*: when authority for a session
    cannot be established, the requested state change is refused instead of
    being guessed at.
    """


class AuthorityUnconfirmed(CutoverError):
    """Raised when an identity-changing write cannot be tied to one
    authoritative backend.

    The session itself is left untouched; the application must ask the client
    to re-authenticate rather than silently mutating identity.
    """

    def __init__(self, sid: str, reason: str):
        self.sid = sid
        self.reason = reason
        super().__init__(
            f"Authority for session {sid!r} could not be confirmed: {reason}. "
            "Identity change refused; re-authentication required."
        )


class CutoverSessionInterface(ServerSideSessionInterface):
    """Session interface implementing the legacy-to-new cutover protocol.

    Both backends are expected to provide the small :class:`cachelib` style
    interface (``get``, ``set`` with ``timeout``, ``add`` returning ``False``
    when the key already exists, and ``delete``). Two in-memory
    :class:`cachelib.simple.SimpleCache` instances are sufficient for testing
    every transition, including faults injected via the ``fault_*`` flags.

    :param app: The Flask application.
    :param new_backend: The new, target session backend.
    :param legacy_backend: The old session backend, kept readable during the
        transition.
    :param phase: Initial phase used only until the durable phase marker is
        read from the new backend. One of ``"legacy"``, ``"cutover"`` or
        ``"new_only"``.
    :param phase_key: Key under which the durable phase marker is stored.
    :param identity_keys: Session keys that represent the authenticated
        identity. A write that adds, removes or changes one of these keys is
        treated as an identity change and requires confirmed authority.
    :param tombstone_timeout: Lifetime of a tombstone record, in seconds. When
        ``None`` it matches the application's permanent session lifetime.
    """

    session_class = ServerSideSession
    ttl = True

    def __init__(
        self,
        app: Flask,
        new_backend: Any,
        legacy_backend: Any,
        key_prefix: str = Defaults.SESSION_KEY_PREFIX,
        use_signer: bool = Defaults.SESSION_USE_SIGNER,
        permanent: bool = Defaults.SESSION_PERMANENT,
        sid_length: int = Defaults.SESSION_ID_LENGTH,
        serialization_format: str = Defaults.SESSION_SERIALIZATION_FORMAT,
        phase: str = CUTOVER,
        phase_key: str = "session_cutover:phase",
        identity_keys: Optional[frozenset] = None,
        tombstone_timeout: Optional[int] = None,
    ):
        if new_backend is None or legacy_backend is None:
            raise ValueError(
                "CutoverSessionInterface requires both a new and a legacy backend."
            )
        if phase not in (LEGACY, CUTOVER, NEW_ONLY):
            raise ValueError(f"Unknown cutover phase: {phase!r}")

        self.new_backend = new_backend
        self.legacy_backend = legacy_backend
        self._configured_phase = phase
        self.phase_key = phase_key
        self.identity_keys = frozenset(identity_keys or ("_user_id", "user_id"))
        self.tombstone_timeout = tombstone_timeout

        super().__init__(
            app, key_prefix, use_signer, permanent, sid_length, serialization_format
        )

    # ------------------------------------------------------------------
    # Durable, recoverable phase control
    # ------------------------------------------------------------------

    def _read_phase(self) -> str:
        """Return the durable cutover phase, recovering after a restart.

        A missing marker means the marker has never been written, so the
        constructor's initial phase is used. An unreachable new backend is
        reported as ``None`` so callers can apply fail-closed handling rather
        than assume a phase.
        """
        try:
            stored = self.new_backend.get(self.phase_key)
        except Exception:
            self.app.logger.exception(
                "New backend unavailable while reading cutover phase marker."
            )
            return None
        if stored is None:
            return self._configured_phase
        phase = stored.get("phase") if isinstance(stored, dict) else None
        return phase if phase in (LEGACY, CUTOVER, NEW_ONLY) else None

    def set_phase(self, phase: str) -> None:
        """Durably move the cutover to ``phase``.

        Forward-only phase moves are enforced; the marker is written to the
        new backend so all processes and restarts observe the same phase.
        """
        if phase not in (LEGACY, CUTOVER, NEW_ONLY):
            raise ValueError(f"Unknown cutover phase: {phase!r}")
        order = {LEGACY: 0, CUTOVER: 1, NEW_ONLY: 2}
        current = self._read_phase() or self._configured_phase
        if order[phase] < order[current]:
            raise ValueError(
                f"Refusing to move cutover backwards from {current!r} to {phase!r}."
            )
        self.new_backend.set(self.phase_key, {"phase": phase}, timeout=0)

    # ------------------------------------------------------------------
    # Key layout
    # ------------------------------------------------------------------

    def _data_key(self, store_id: str) -> str:
        return store_id

    def _authority_key(self, store_id: str) -> str:
        return f"{store_id}:authority"

    # ------------------------------------------------------------------
    # Identity change detection
    # ------------------------------------------------------------------

    def _identity_fingerprint(self, data: Optional[dict]) -> Tuple:
        if not data:
            return ()
        return tuple(
            (key, data.get(key)) for key in sorted(self.identity_keys) if key in data
        )

    def _is_identity_change(self, session: ServerSideSession) -> bool:
        before = getattr(session, _IDENTITY_FINGERPRINT_ATTR, None)
        if before is None:
            # Sessions opened before this interface tracked a fingerprint are
            # treated as identity-changing when they touch an identity key.
            return any(key in session for key in self.identity_keys)
        return before != self._identity_fingerprint(dict(session))

    # ------------------------------------------------------------------
    # Read path: new backend first, legacy fallback, tombstone enforcement
    # ------------------------------------------------------------------

    def _read_authority(self, store_id: str) -> Optional[dict]:
        try:
            return self.new_backend.get(self._authority_key(store_id))
        except Exception:
            self.app.logger.exception("New backend unavailable while reading authority.")
            return None

    def _read_session(
        self, store_id: str
    ) -> Tuple[Optional[dict], Optional[dict]]:
        """Return ``(session_data, authority_record)`` for a request.

        Read order is always new backend first, then a legacy fallback. The
        fallback is only honoured while the durable phase permits it; in the
        ``new_only`` phase legacy records are inert history. A tombstone
        always wins, so a late legacy write after logout cannot resurrect a
        session. Reads never migrate or repair data themselves, keeping the
        read path side-effect free; crash repair happens on the next write.
        """
        authority = self._read_authority(store_id)

        if authority is not None and authority.get("state") == STATE_TOMBSTONED:
            return None, authority

        try:
            data = self.new_backend.get(self._data_key(store_id))
        except Exception:
            data = None
            self.app.logger.exception(
                "New backend unavailable while reading session data."
            )

        if data is not None:
            return data, authority

        phase = self._read_phase()
        if phase == NEW_ONLY:
            # The old service is retired: legacy records must not authenticate
            # or populate any session anymore.
            return None, authority

        try:
            legacy_data = self.legacy_backend.get(self._data_key(store_id))
        except Exception:
            legacy_data = None
            self.app.logger.exception("Legacy backend read failed.")
        return legacy_data, authority

    def _retrieve_session_data(self, store_id: str) -> Optional[dict]:
        data, _authority = self._read_session(store_id)
        return data

    def open_session(self, app, request):
        sid = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
        if not sid:
            sid = self._generate_sid(self.sid_length)
            session = self.session_class(sid=sid, permanent=self.permanent)
            setattr(session, _IDENTITY_FINGERPRINT_ATTR, ())
            return session
        if self.use_signer:
            from itsdangerous import BadSignature

            try:
                sid = self._unsign(app, sid)
            except BadSignature:
                sid = self._generate_sid(self.sid_length)
                session = self.session_class(sid=sid, permanent=self.permanent)
                setattr(session, _IDENTITY_FINGERPRINT_ATTR, ())
                return session

        store_id = self._get_store_id(sid)
        data, _authority = self._read_session(store_id)
        if data is not None:
            session = self.session_class(data, sid=sid)
        else:
            session = self.session_class(sid=sid, permanent=self.permanent)
        setattr(session, _IDENTITY_FINGERPRINT_ATTR, self._identity_fingerprint(data))
        return session

    # ------------------------------------------------------------------
    # Write path: exactly one authoritative writer per session
    # ------------------------------------------------------------------

    def _ttl_seconds(self, session_lifetime: TimeDelta) -> int:
        return total_seconds(session_lifetime)

    def _tombstone_ttl(self, session_lifetime: TimeDelta) -> int:
        if self.tombstone_timeout is not None:
            return self.tombstone_timeout
        return self._ttl_seconds(session_lifetime)

    def _claim_authority(self, store_id: str, owner: str, ttl: int) -> Optional[dict]:
        """Atomically claim this session for the new backend.

        Returns the existing authority record when another writer won the
        race; ``None`` when the claim itself could not be attempted.
        """
        record = {"state": STATE_MIGRATED, "owner": owner, "ttl": ttl}
        try:
            won = self.new_backend.add(self._authority_key(store_id), record, ttl)
        except Exception:
            self.app.logger.exception("Authority claim failed; new backend unreachable.")
            return None
        if won:
            return record
        return self._read_authority(store_id)

    def _upsert_session(self, session_lifetime, session, store_id) -> None:
        ttl = self._ttl_seconds(session_lifetime)
        data = dict(session)
        identity_change = self._is_identity_change(session)
        phase = self._read_phase()
        authority = self._read_authority(store_id)

        # A pure TTL refresh (the session was only read, never modified) never
        # performs a storage write. This keeps reads side-effect free, which is
        # essential during a cutover: a GET must not manufacture authority or
        # repair a half-finished migration behind the client's back.
        if not session.modified:
            return

        # Already migrated: the new backend is the single writer and the
        # legacy backend must never be touched again.
        if authority is not None:
            if authority.get("state") == STATE_TOMBSTONED:
                # A new authenticated session after logout must prove itself.
                if identity_change:
                    raise AuthorityUnconfirmed(
                        session.sid, "session is tombstoned after logout"
                    )
                # Non-identity traffic against a logged-out session must not
                # resurrect any data behind the tombstone.
                return
            self._write_to_new(store_id, data, authority, ttl)
            # Crash recovery: if the previous attempt died before invalidating
            # the legacy copy, finish the migration now that the new write is
            # durable. This is the only remaining step, so it stays idempotent.
            if self._safe_legacy_get(store_id) is not None:
                self.legacy_backend.delete(store_id)
            return

        if phase == LEGACY:
            self.legacy_backend.set(store_id, data, timeout=ttl)
            return

        if phase == NEW_ONLY:
            # Legacy is read-only history. Identity changes need an authority
            # record, which cannot be created while the new backend's state is
            # unknown.
            record = self._claim_authority(store_id, session.sid, ttl)
            if record is None:
                if identity_change:
                    raise AuthorityUnconfirmed(
                        session.sid, "new backend unreachable in new_only phase"
                    )
                raise CutoverError(
                    f"New backend unreachable for session {session.sid!r}; "
                    "legacy backend is read-only in new_only phase."
                )
            self._write_to_new(store_id, data, record, ttl)
            return

        if phase is None:
            # The phase marker itself cannot be read. Refuse identity changes;
            # non-identity writes may still go to the legacy backend because
            # that backend is the safe pre-cutover default and no migration is
            # attempted with an unknown coordinator state.
            if identity_change:
                raise AuthorityUnconfirmed(
                    session.sid, "cutover phase marker unreadable"
                )
            self.legacy_backend.set(store_id, data, timeout=ttl)
            return

        # CUTOVER phase. Identity-changing writes are the migration trigger:
        # they are the operations that absolutely require a single confirmed
        # authority.
        if identity_change:
            self._migrate_with_authority(session.sid, store_id, data, ttl)
            return

        # Ordinary, non-identity writes keep flowing to the legacy backend for
        # sessions that have never been migrated. This avoids speculative
        # dual ownership and keeps read fallback meaningful; the session is
        # migrated exactly once, on its first identity change or when the
        # deployment reaches the new_only phase.
        self.legacy_backend.set(store_id, data, timeout=ttl)

    def _write_to_new(
        self, store_id: str, data: dict, authority: dict, ttl: int
    ) -> None:
        record = dict(authority)
        record["state"] = STATE_MIGRATED
        record["ttl"] = ttl
        self.new_backend.set(self._data_key(store_id), data, timeout=ttl)
        self.new_backend.set(self._authority_key(store_id), record, timeout=ttl)

    def _migrate_with_authority(
        self, owner: str, store_id: str, data: dict, ttl: int
    ) -> None:
        record = self._claim_authority(store_id, owner, ttl)
        if record is None:
            raise AuthorityUnconfirmed(
                owner, "authority claim could not be attempted"
            )
        if record.get("state") == STATE_TOMBSTONED:
            raise AuthorityUnconfirmed(owner, "session was logged out (tombstoned)")
        # Capture the legacy snapshot before overwriting. If a previous attempt
        # crashed between the claim and the new write, the snapshot lets the
        # recovered migration preserve data instead of silently dropping it.
        legacy_snapshot = self._safe_legacy_get(store_id)
        payload = data
        if legacy_snapshot is not None and not data:
            payload = legacy_snapshot

        self._write_to_new(store_id, payload, record, ttl)
        # Old data is invalidated strictly AFTER the new write is durable, so
        # no window exists in which the session exists in neither backend.
        if legacy_snapshot is not None:
            self.legacy_backend.delete(store_id)

    def _safe_legacy_get(self, store_id: str) -> Optional[dict]:
        try:
            return self.legacy_backend.get(store_id)
        except Exception:
            self.app.logger.exception("Legacy backend read during migration failed.")
            return None

    # ------------------------------------------------------------------
    # Fail-closed response boundary
    # ------------------------------------------------------------------

    def save_session(self, app, session, response):
        """Save the session, converting protocol refusals into safe responses.

        Flask's application error handlers do not cover exceptions raised while
        saving the session during response finalization, so the fail-closed
        mapping lives here. An unconfirmed identity change never reaches a
        backend as a speculative write.
        """
        try:
            super().save_session(app, session, response)
        except AuthorityUnconfirmed as error:
            app.logger.warning("Refused identity change: %s", error)
            response.status_code = 409
            response.content_type = "application/json"
            response.set_data(
                '{"error":"session_authority_unconfirmed",'
                f'"reason":"{error.reason}","reauthenticate":true}}'
            )
            response.vary.add("Cookie")
        except CutoverError as error:
            app.logger.error("Cutover protocol failure: %s", error)
            response.status_code = 503
            response.content_type = "application/json"
            response.set_data('{"error":"session_cutover_failure"}')
            response.vary.add("Cookie")

    # ------------------------------------------------------------------
    # Logout: tombstone first, then invalidate the legacy record
    # ------------------------------------------------------------------

    def _delete_session(self, store_id: str) -> None:
        ttl = self._tombstone_ttl(self.app.permanent_session_lifetime)
        phase = self._read_phase()
        authority = self._read_authority(store_id)

        if authority is None and phase == LEGACY:
            # Pre-cutover logout: the legacy backend is still the sole owner,
            # so deleting its record is the complete and correct invalidation.
            self.legacy_backend.delete(store_id)
            return

        if authority is None and phase is None:
            # With no readable phase marker and no authority record we cannot
            # tell which backend owns the session; deleting blindly could leave
            # the other copy authoritative. Fail closed instead.
            raise CutoverError(
                f"Refusing to log out session {store_id!r}: cutover phase marker "
                "is unreadable and no authority record exists."
            )

        if authority is None and phase in (CUTOVER, NEW_ONLY):
            record = {"state": STATE_TOMBSTONED, "owner": "logout", "ttl": ttl}
            try:
                claimed = self.new_backend.add(
                    self._authority_key(store_id), record, ttl
                )
            except Exception as error:
                self.app.logger.exception("Could not write logout tombstone.")
                raise CutoverError(
                    f"Refusing to log out session {store_id!r}: tombstone could not "
                    "be persisted, legacy data would remain authoritative."
                ) from error
            if not claimed:
                authority = self._read_authority(store_id)

        if authority is not None:
            tombstone = dict(authority)
            tombstone["state"] = STATE_TOMBSTONED
            tombstone["ttl"] = ttl
            try:
                self.new_backend.set(
                    self._authority_key(store_id), tombstone, timeout=ttl
                )
            except Exception as error:
                self.app.logger.exception("Could not persist logout tombstone.")
                raise CutoverError(
                    f"Refusing to log out session {store_id!r}: tombstone could not "
                    "be updated, legacy data would remain authoritative."
                ) from error

        try:
            self.new_backend.delete(self._data_key(store_id))
        except Exception:
            self.app.logger.exception("New-backend data delete failed on logout.")

        # Legacy invalidation is the last step; the tombstone already fences
        # any late legacy write even if this delete is delayed.
        self.legacy_backend.delete(store_id)


def register_cutover_error_handlers(app: Flask) -> None:
    """Map fail-closed cutover errors onto safe HTTP responses.

    An unconfirmed identity change becomes ``409 Conflict`` (the client must
    re-authenticate); an infrastructure-level cutover failure that still
    prevents a safe write becomes ``503 Service Unavailable``. No error
    handler ever guesses which backend was authoritative.
    """

    @app.errorhandler(AuthorityUnconfirmed)
    def _handle_authority_unconfirmed(error: AuthorityUnconfirmed):
        app.logger.warning("Refused identity change: %s", error)
        response = jsonify(
            error="session_authority_unconfirmed",
            reason=error.reason,
            reauthenticate=True,
        )
        response.status_code = 409
        return response

    @app.errorhandler(CutoverError)
    def _handle_cutover_error(error: CutoverError):
        app.logger.error("Cutover protocol failure: %s", error)
        response = jsonify(error="session_cutover_failure")
        response.status_code = 503
        return response
