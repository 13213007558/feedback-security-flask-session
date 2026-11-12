import secrets
import warnings
from abc import ABC, abstractmethod
from contextlib import suppress

try:
    import cPickle as pickle
except ImportError:
    import pickle

import random
from datetime import timedelta as TimeDelta
from typing import Any, Dict, Optional

import msgspec
from flask import Flask, Request, Response
from flask.sessions import SessionInterface as FlaskSessionInterface
from flask.sessions import SessionMixin
from itsdangerous import BadSignature, Signer, want_bytes
from werkzeug.datastructures import CallbackDict

from ._utils import retry_query
from .defaults import Defaults


class SessionRegenerationError(RuntimeError):
    """Raised when a session id could not be rotated safely.

    The session id is still changed to a fresh, unused value before this
    exception is raised. This prevents an application that catches the error
    from saving the new identity under the old, potentially attacker-known
    session id. The exception signals that the previous session record could
    not be removed or verified, not that the old id is still safe to use.
    """


class ServerSideSession(CallbackDict, SessionMixin):
    """Baseclass for server-side based sessions. This can be accessed through ``flask.session``.

    .. attribute:: sid

    Session id, internally we use :func:`secrets.token_urlsafe` to generate one
    session id.

    .. attribute:: modified

    When data is changed, this is set to ``True``. Only the session dictionary
    itself is tracked; if the session contains mutable data (for example a nested
    dict) then this must be set to ``True`` manually when modifying that data. The
    session cookie will only be written to the response if this is ``True``.

    .. attribute:: accessed

    When data is read (or attempted read) or written, this is set to ``True``. Used by
    :class:`.ServerSideSessionInterface` to add a ``Vary: Cookie``
    header, which allows caching proxies to cache different pages for
    different users.

    Default is ``False``.

    .. attribute:: permanent

    This sets and reflects the ``'_permanent'`` key in the dict.

    Default is ``False``.

    """

    def __bool__(self) -> bool:
        return bool(dict(self)) and self.keys() != {"_permanent"}

    def __init__(
        self,
        initial: Optional[Dict[str, Any]] = None,
        sid: Optional[str] = None,
        permanent: Optional[bool] = None,
    ):
        def on_update(self) -> None:
            self.modified = True
            self.accessed = True

        CallbackDict.__init__(self, initial, on_update)
        self.sid = sid
        self._regeneration_failed = False
        self._rotated = False
        if permanent:
            self.permanent = permanent
        self.modified = False
        self.accessed = False

    def __getitem__(self, key: str) -> Any:
        self.accessed = True
        return super().__getitem__(key)

    def get(self, key: str, default: Any = None) -> Any:
        self.accessed = True
        return super().get(key, default)

    def setdefault(self, key: str, default: Any = None) -> Any:
        self.accessed = True
        return super().setdefault(key, default)

    def clear(self) -> None:
        """Clear the session except for the '_permanent' key."""
        permanent = self.get("_permanent", False)
        super().clear()
        self["_permanent"] = permanent
        # Clearing after a rotation expresses deletion intent; a later
        # regenerate() sets this flag again.
        self._rotated = False


class Serializer(ABC):
    """Baseclass for session serialization."""

    @abstractmethod
    def dumps(self, serialized_data: bytes) -> dict:
        """Deserialize the session data."""
        raise NotImplementedError()

    @abstractmethod
    def loads(self, session: ServerSideSession) -> bytes:
        """Serialize the session data."""
        raise NotImplementedError()


class MsgSpecSerializer(Serializer):
    def __init__(self, app: Flask, format: str):
        self.app: Flask = app
        self.encoder: msgspec.msgpack.Encoder or msgspec.json.Encoder
        self.decoder: msgspec.msgpack.Decoder or msgspec.json.Decoder
        self.alternate_decoder: msgspec.msgpack.Decoder or msgspec.json.Decoder

        if format == "msgpack":
            self.encoder = msgspec.msgpack.Encoder()
            self.decoder = msgspec.msgpack.Decoder()
            self.alternate_decoder = msgspec.json.Decoder()
        elif format == "json":
            self.encoder = msgspec.json.Encoder()
            self.decoder = msgspec.json.Decoder()
            self.alternate_decoder = msgspec.msgpack.Decoder()
        else:
            raise ValueError(f"Unsupported serialization format: {format}")

    def dumps(self, data: dict) -> bytes:
        """Serialize the session data."""
        try:
            return self.encoder.encode(data)
        except Exception as e:
            self.app.logger.error(f"Failed to serialize session data: {e}")
            raise

    def loads(self, serialized_data: bytes) -> dict:
        """Deserialize the session data."""
        # TODO: Remove the pickle fallback in 1.0.0
        with suppress(msgspec.DecodeError):
            return self.decoder.decode(serialized_data)
        with suppress(msgspec.DecodeError):
            return self.alternate_decoder.decode(serialized_data)
        with suppress(pickle.UnpicklingError):
            return pickle.loads(serialized_data)
        # If all decoders fail, raise the final exception
        self.app.logger.error("Failed to deserialize session data", exc_info=True)
        raise pickle.UnpicklingError("Failed to deserialize session data")


class ServerSideSessionInterface(FlaskSessionInterface, ABC):
    """Used to open a :class:`flask.sessions.ServerSideSessionInterface` instance."""

    session_class = ServerSideSession
    serializer = None
    ttl = True

    def __init__(
        self,
        app: Flask,
        key_prefix: str = Defaults.SESSION_KEY_PREFIX,
        use_signer: bool = Defaults.SESSION_USE_SIGNER,
        permanent: bool = Defaults.SESSION_PERMANENT,
        sid_length: int = Defaults.SESSION_ID_LENGTH,
        serialization_format: str = Defaults.SESSION_SERIALIZATION_FORMAT,
        cleanup_n_requests: Optional[int] = Defaults.SESSION_CLEANUP_N_REQUESTS,
    ):
        self.app = app
        self.key_prefix = key_prefix
        self.use_signer = use_signer
        if use_signer:
            warnings.warn(
                "The 'use_signer' option is deprecated and will be removed in the next minor release. "
                "Please update your configuration accordingly or open an issue.",
                DeprecationWarning,
                stacklevel=1,
            )
        self.permanent = permanent
        self.sid_length = sid_length
        self.has_same_site_capability = hasattr(self, "get_cookie_samesite")
        self.cleanup_n_requests = cleanup_n_requests

        # Cleanup settings for non-TTL databases only
        if getattr(self, "ttl", None) is False:
            if self.cleanup_n_requests:
                self.app.before_request(self._cleanup_n_requests)
            else:
                self._register_cleanup_app_command()

        # Set the serialization format
        self.serializer = MsgSpecSerializer(format=serialization_format, app=app)

    # INTERNAL METHODS

    def _generate_sid(self, session_id_length: int) -> str:
        """Generate a random session id."""
        return secrets.token_urlsafe(session_id_length)

    # TODO: Remove in 1.0.0
    def _get_signer(self, app: Flask) -> Signer:
        if not hasattr(app, "secret_key") or not app.secret_key:
            raise KeyError("SECRET_KEY must be set when SESSION_USE_SIGNER=True")
        return Signer(app.secret_key, salt="flask-session", key_derivation="hmac")

    # TODO: Remove in 1.0.0
    def _unsign(self, app, sid: str) -> str:
        signer = self._get_signer(app)
        sid_as_bytes = signer.unsign(sid)
        sid = sid_as_bytes.decode()
        return sid

    # TODO: Remove in 1.0.0
    def _sign(self, app, sid: str) -> str:
        signer = self._get_signer(app)
        sid_as_bytes = want_bytes(sid)
        return signer.sign(sid_as_bytes).decode("utf-8")

    def _get_store_id(self, sid: str) -> str:
        return self.key_prefix + sid

    def should_set_storage(self, app: Flask, session: ServerSideSession) -> bool:
        """Used by session backends to determine if session in storage
        should be set for this session cookie for this response. If the session
        has been modified, the session is set to storage. If
        the ``SESSION_REFRESH_EACH_REQUEST`` config is true, the session is
        always set to storage. In the second case, this means refreshing the
        storage expiry even if the session has not been modified.

        .. versionadded:: 0.7.0
        """

        return session.modified or app.config["SESSION_REFRESH_EACH_REQUEST"]

    # CLEANUP METHODS FOR NON TTL DATABASES

    def _register_cleanup_app_command(self):
        """
        Register a custom Flask CLI command for cleaning up expired sessions.

        Run the command with `flask session_cleanup`. Run with a cron job
        or scheduler such as Heroku Scheduler to automatically clean up expired sessions.
        """

        @self.app.cli.command("session_cleanup")
        def session_cleanup():
            with self.app.app_context():
                self._delete_expired_sessions()

    def _cleanup_n_requests(self) -> None:
        """
        Delete expired sessions on average every N requests.

        This is less desirable than using the scheduled app command cleanup as it may
        slow down some requests but may be useful for rapid development.
        """
        if self.cleanup_n_requests and random.randint(0, self.cleanup_n_requests) == 0:
            self._delete_expired_sessions()

    # SECURITY API METHODS

    def regenerate(self, session: ServerSideSession) -> None:
        """Regenerate the session id for the given session.

        Can be used by calling ``flask.session_interface.regenerate()``,
        typically right after a successful login to mitigate session fixation.

        The session id is rotated regardless of whether the session currently
        contains data. This covers flows that clear an anonymous session first
        and write the authenticated identity afterwards. Calling this method
        more than once in the same request always produces a different id; ids
        returned by earlier calls are never persisted and cannot load data.

        The previous record is deleted and its absence is verified. If the
        backend cannot delete the old record, or still returns data for it
        afterwards, :class:`SessionRegenerationError` is raised. The session
        still receives a fresh id before the exception is raised, so a caller
        that catches the error never saves the new identity under the old id.
        The new record is written by :meth:`save_session`; therefore a rotation
        only takes effect once the response is saved successfully.
        """
        if session.sid is None:
            raise SessionRegenerationError(
                "Cannot regenerate a session that has no session id."
            )

        old_sid = session.sid
        previous_store_id = self._get_store_id(old_sid)
        new_sid = self._generate_sid(self.sid_length)

        if new_sid == old_sid:
            raise SessionRegenerationError(
                "The session id generator returned an id that is already in use."
            )

        # Some backends do not report a delete result and may silently fail.
        # Treat a reported failure as fatal when a record existed, then verify
        # the old id cannot load any session data before claiming success.
        try:
            had_previous_record = (
                self._retrieve_session_data(previous_store_id) is not None
            )
            deleted = self._delete_session(previous_store_id)
            if had_previous_record and deleted is False:
                raise SessionRegenerationError(
                    "The previous session record could not be deleted."
                )
            if self._retrieve_session_data(previous_store_id) is not None:
                raise SessionRegenerationError(
                    "The previous session record is still readable after deletion."
                )
        except Exception as e:
            # Keep the fresh id even on failure. If the caller catches the
            # exception, the new identity must never be written under the old,
            # potentially attacker-known id.
            session.sid = new_sid
            session.modified = True
            session._regeneration_failed = True
            if isinstance(e, SessionRegenerationError):
                raise
            raise SessionRegenerationError(
                "The previous session record could not be deleted or verified."
            ) from e

        session.sid = new_sid
        session._regeneration_failed = False
        session._rotated = True
        session.modified = True

    # METHODS OVERRIDE FLASK SESSION INTERFACE

    def save_session(
        self, app: Flask, session: ServerSideSession, response: Response
    ) -> None:

        # Get the domain and path for the cookie from the app
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        name = self.get_cookie_name(app)

        # Generate a prefixed session id
        store_id = self._get_store_id(session.sid)

        # Add a "Vary: Cookie" header if the session was accessed at all.
        # This assumes the app is checking the session values in a request that
        # behaves differently based on those values. ie. session.get("is_authenticated")
        if session.accessed:
            response.vary.add("Cookie")

        if session._regeneration_failed:
            # A failed rotation must not produce a cookie or a stored record.
            # The failed login/session setup has to visible as an error instead
            # of half-completing with a credential the backend could not secure.
            raise SessionRegenerationError(
                "The session was not saved because a previous regeneration failed."
            )

        # If the session is empty, do not save it to the database or set a cookie
        if not session:
            # A session that was rotated while empty must still bind the client
            # to the new id. Otherwise the browser keeps sending the old id,
            # which was deleted, and a later request silently gets a third id.
            # An empty session has no data worth storing, but the cookie keeps
            # the rotation visible across requests until the identity is set.
            if session._rotated:
                empty_session = self.session_class(
                    {"_permanent": session.get("_permanent", False)},
                    sid=session.sid,
                )
                success = self._upsert_session(
                    app.permanent_session_lifetime,
                    empty_session,
                    store_id,
                )
                if success is False or self._retrieve_session_data(store_id) is None:
                    raise RuntimeError("The session record could not be saved.")
                self._set_session_cookie(app, response, session, domain, path, name)
            elif session.modified:
                # The session was deleted (empty and modified), delete the saved session from the database and tell the client to delete the cookie
                self._delete_session(store_id)
                response.delete_cookie(key=name, domain=domain, path=path)
                response.vary.add("Cookie")
            return

        if not self.should_set_storage(app, session) and not session._rotated:
            return

        # Update existing or create new session in the database
        upsert_result = self._upsert_session(
            app.permanent_session_lifetime, session, store_id
        )
        if upsert_result is False:
            # Never send a cookie for a session that was not persisted; doing
            # so would hand out a credential whose record does not exist.
            raise RuntimeError("The session record could not be saved.")

        if session._rotated and self._retrieve_session_data(store_id) is None:
            raise RuntimeError("The session record could not be verified as saved.")

        if not self.should_set_cookie(app, session) and not session._rotated:
            return

        self._set_session_cookie(app, response, session, domain, path, name)

    def _set_session_cookie(
        self,
        app: Flask,
        response: Response,
        session: ServerSideSession,
        domain: Optional[str],
        path: str,
        name: str,
    ) -> None:
        # Get the additional required cookie settings
        value = self._sign(app, session.sid) if self.use_signer else session.sid
        expires = self.get_expiration_time(app, session)
        httponly = self.get_cookie_httponly(app)
        secure = self.get_cookie_secure(app)
        samesite = (
            self.get_cookie_samesite(app) if self.has_same_site_capability else None
        )

        # Set the browser cookie
        response.set_cookie(
            key=name,
            value=value,
            expires=expires,
            httponly=httponly,
            domain=domain,
            path=path,
            secure=secure,
            samesite=samesite,
        )
        response.vary.add("Cookie")

    def open_session(self, app: Flask, request: Request) -> ServerSideSession:
        # Get the session ID from the cookie
        sid = request.cookies.get(app.config["SESSION_COOKIE_NAME"])

        # If there's no session ID, generate a new one
        if not sid:
            sid = self._generate_sid(self.sid_length)
            return self.session_class(sid=sid, permanent=self.permanent)
        # If the session ID is signed, unsign it
        if self.use_signer:
            try:
                sid = self._unsign(app, sid)
            except BadSignature:
                sid = self._generate_sid(self.sid_length)
                return self.session_class(sid=sid, permanent=self.permanent)

        # Retrieve the session data from the database
        store_id = self._get_store_id(sid)
        saved_session_data = self._retrieve_session_data(store_id)

        # If the saved session exists, load the session data from the document
        if saved_session_data is not None:
            return self.session_class(saved_session_data, sid=sid)

        # If the saved session does not exist, create a new session
        sid = self._generate_sid(self.sid_length)
        return self.session_class(sid=sid, permanent=self.permanent)

    # METHODS TO BE IMPLEMENTED BY SUBCLASSES

    @abstractmethod
    @retry_query()  # use only when retry not supported directly by the client
    def _retrieve_session_data(self, store_id: str) -> Optional[dict]:
        """Get the saved session from the session storage."""
        raise NotImplementedError()

    @abstractmethod
    @retry_query()  # use only when retry not supported directly by the client
    def _delete_session(self, store_id: str) -> Optional[bool]:
        """Delete session from the session storage.

        Returns ``True`` when the record is known to be deleted, ``False`` when
        the backend reports that deletion failed, and ``None`` when the backend
        does not report a result. ``regenerate`` verifies deletion by reading
        the old record after this call regardless of the return value.
        """
        raise NotImplementedError()

    @abstractmethod
    @retry_query()  # use only when retry not supported directly by the client
    def _upsert_session(
        self, session_lifetime: TimeDelta, session: ServerSideSession, store_id: str
    ) -> Optional[bool]:
        """Update existing or create new session in the session storage.

        Returns ``True`` when the record is known to be saved, ``False`` when
        the backend reports that saving failed, and ``None`` when the backend
        does not report a result.
        """
        raise NotImplementedError()

    @retry_query()  # use only when retry not supported directly by the client
    def _delete_expired_sessions(self) -> None:
        """Delete expired sessions from the session storage. Only required for non-TTL databases."""
        pass
