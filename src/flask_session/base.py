import secrets
import warnings
from abc import ABC, abstractmethod
from contextlib import contextmanager, suppress

try:
    import cPickle as pickle
except ImportError:
    import pickle

import random
from datetime import timedelta as TimeDelta
from typing import Any, Dict, Iterable, Mapping, Optional, Union

import msgspec
from flask import Flask, Request, Response
from flask.sessions import SessionInterface as FlaskSessionInterface
from flask.sessions import SessionMixin
from itsdangerous import BadSignature, Signer, want_bytes
from werkzeug.datastructures import CallbackDict

from ._protected import wrap_value
from ._utils import retry_query
from .defaults import Defaults
from .exceptions import ProtectedFieldError


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

    .. attribute:: protected_fields

    Optional mapping of protected session fields to the set of scopes allowed
    to write them. When empty (the default) the session behaves exactly like an
    ordinary dictionary and every key remains freely writable. When a field is
    listed, any write to it requires one of the configured scopes to be active
    for the current request through :meth:`grant_scopes`. Ordinary, unlisted
    fields keep their original dictionary behavior.

    """

    def __bool__(self) -> bool:
        return bool(dict(self)) and self.keys() != {"_permanent"}

    def __init__(
        self,
        initial: Optional[Dict[str, Any]] = None,
        sid: Optional[str] = None,
        permanent: Optional[bool] = None,
        protected_fields: Optional[
            Mapping[str, Union[str, Iterable[str]]]
        ] = None,
    ):
        def on_update(self) -> None:
            self.modified = True
            self.accessed = True

        CallbackDict.__init__(self, initial, on_update)
        # Normalize the protected field policy into {field: frozenset(scopes)}.
        # Stored on the session object rather than the mapping, so it is never
        # serialized and never leaks into stored session data.
        self.protected_fields: Dict[str, frozenset] = {
            field: frozenset(
                (scopes,) if isinstance(scopes, str) else tuple(scopes)
            )
            for field, scopes in (protected_fields or {}).items()
        }
        # Scopes granted for the lifetime of this request-scoped session
        # instance. A fresh session is created per request, so scopes can never
        # carry over between requests or concurrent requests.
        self._active_scopes: set = set()
        self.sid = sid
        if permanent:
            self.permanent = permanent
        self.modified = False
        self.accessed = False
        # Wrap nested mutable values of protected fields loaded from storage so
        # in-place nested mutations are covered by the same scope checks.
        for field in self.protected_fields:
            if field in CallbackDict.keys(self):
                value = CallbackDict.__getitem__(self, field)
                CallbackDict.__setitem__(
                    self, field, wrap_value(value, field, self._enforce_scope)
                )

    # PROTECTED FIELD / SCOPE API

    def is_protected(self, key: str) -> bool:
        """Return whether writes to ``key`` require an explicit scope."""
        return key in self.protected_fields

    def can_write(self, key: str) -> bool:
        """Return whether the currently active scopes allow writing ``key``."""
        required = self.protected_fields.get(key)
        return required is None or bool(required & self._active_scopes)

    def _enforce_scope(self, key: str) -> None:
        """Raise :class:`ProtectedFieldError` if ``key`` is not writable now."""
        required = self.protected_fields.get(key)
        if required is not None and not (required & self._active_scopes):
            raise ProtectedFieldError(
                key=key,
                required_scopes=required,
                active_scopes=frozenset(self._active_scopes),
            )

    @contextmanager
    def grant_scopes(self, *scopes: str):
        """Temporarily grant write scopes for this session (request scoped).

        Only active for the duration of the ``with`` block and only on this
        session instance. On exit the previously active scopes are restored,
        so nested grants and early exceptions cannot leak a scope to later
        code or to a concurrent request::

            with session.grant_scopes("auth"):
                session["user_id"] = current_user.id

        Ordinary fields remain writable with or without any granted scope.
        """
        previous = set(self._active_scopes)
        self._active_scopes = previous | set(scopes)
        try:
            yield self
        finally:
            self._active_scopes = previous

    # READ METHODS (unchanged semantics apart from accessed tracking)

    def __getitem__(self, key: str) -> Any:
        self.accessed = True
        return super().__getitem__(key)

    def get(self, key: str, default: Any = None) -> Any:
        self.accessed = True
        return super().get(key, default)

    # WRITE / MUTATING METHODS

    def __setitem__(self, key: str, value: Any) -> None:
        self._enforce_scope(key)
        if self.is_protected(key):
            value = wrap_value(value, key, self._enforce_scope)
        super().__setitem__(key, value)

    def __delitem__(self, key: str) -> None:
        self._enforce_scope(key)
        super().__delitem__(key)

    def setdefault(self, key: str, default: Any = None) -> Any:
        self.accessed = True
        if key not in self:
            self._enforce_scope(key)
            if self.is_protected(key):
                default = wrap_value(default, key, self._enforce_scope)
            super().__setitem__(key, default)
        return super().__getitem__(key)

    def update(self, *args: Any, **kwargs: Any) -> None:
        """Merge keys into the session, enforcing protected field scopes.

        Every targeted protected field is validated before any value is
        written, so a refusal leaves the session completely untouched.
        """
        changes: Dict[str, Any] = {}
        if args:
            if len(args) > 1:
                raise TypeError(
                    f"update expected at most 1 argument, got {len(args)}"
                )
            other = args[0]
            if hasattr(other, "keys"):
                for key in other:
                    changes[key] = other[key]
            else:
                changes.update(other)
        changes.update(kwargs)

        # Validate all writes up front to preserve the previous consistent
        # state when any single protected field is unauthorized.
        for key in changes:
            self._enforce_scope(key)
        for key, value in changes.items():
            if self.is_protected(key):
                value = wrap_value(value, key, self._enforce_scope)
            super().__setitem__(key, value)

    def pop(self, key: str, *default: Any) -> Any:
        self._enforce_scope(key)
        return super().pop(key, *default)

    def popitem(self) -> Any:
        # Popitem targets an arbitrary key; refuse unless every remaining key
        # is writable, otherwise a protected value could be removed blindly.
        for key in CallbackDict.keys(self):
            self._enforce_scope(key)
        return super().popitem()

    def clear(self) -> None:
        """Clear the session except for the '_permanent' key.

        Protected fields are retained unless the active scopes authorize their
        removal. Refusal happens before anything is removed, keeping the
        previous state intact.
        """
        permanent = self.get("_permanent", False)
        for key in CallbackDict.keys(self):
            if key != "_permanent":
                self._enforce_scope(key)
        super().clear()
        self["_permanent"] = permanent


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

        # Protected field policy as {field: frozenset(scopes)}. Empty by
        # default, which leaves ordinary dictionary behavior untouched. The
        # Session factory overwrites this from SESSION_PROTECTED_FIELDS after
        # the concrete backend has been constructed.
        self.protected_fields: Dict[str, frozenset] = {}

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

    def _make_session(
        self,
        initial: Optional[dict] = None,
        sid: Optional[str] = None,
        permanent: Optional[bool] = None,
    ) -> ServerSideSession:
        """Create a session object wired with the protected field policy.

        Centralizing construction keeps every backend on the same policy
        without each backend having to know about protected fields.
        """
        return self.session_class(
            initial=initial,
            sid=sid,
            permanent=self.permanent if permanent is None else permanent,
            protected_fields=self.protected_fields,
        )

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
        """Regenerate the session id for the given session. Can be used by calling ``flask.session_interface.regenerate()``."""
        if session:
            # Remove the old session from storage
            self._delete_session(self._get_store_id(session.sid))
            # Generate a new session ID
            new_sid = self._generate_sid(self.sid_length)
            session.sid = new_sid
            # Mark the session as modified to ensure it gets saved
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

        # If the session is empty, do not save it to the database or set a cookie
        if not session:
            # If the session was deleted (empty and modified), delete the saved session  from the database and tell the client to delete the cookie
            if session.modified:
                self._delete_session(store_id)
                response.delete_cookie(key=name, domain=domain, path=path)
                response.vary.add("Cookie")
            return

        if not self.should_set_storage(app, session):
            return

        # Update existing or create new session in the database
        self._upsert_session(app.permanent_session_lifetime, session, store_id)

        if not self.should_set_cookie(app, session):
            return

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
            return self._make_session(sid=sid)
        # If the session ID is signed, unsign it
        if self.use_signer:
            try:
                sid = self._unsign(app, sid)
            except BadSignature:
                sid = self._generate_sid(self.sid_length)
                return self._make_session(sid=sid)

        # Retrieve the session data from the database
        store_id = self._get_store_id(sid)
        saved_session_data = self._retrieve_session_data(store_id)

        # If the saved session exists, load the session data from the document
        if saved_session_data is not None:
            return self._make_session(saved_session_data, sid=sid)

        # If the saved session does not exist, create a new session
        sid = self._generate_sid(self.sid_length)
        return self._make_session(sid=sid)

    # METHODS TO BE IMPLEMENTED BY SUBCLASSES

    @abstractmethod
    @retry_query()  # use only when retry not supported directly by the client
    def _retrieve_session_data(self, store_id: str) -> Optional[dict]:
        """Get the saved session from the session storage."""
        raise NotImplementedError()

    @abstractmethod
    @retry_query()  # use only when retry not supported directly by the client
    def _delete_session(self, store_id: str) -> None:
        """Delete session from the session storage."""
        raise NotImplementedError()

    @abstractmethod
    @retry_query()  # use only when retry not supported directly by the client
    def _upsert_session(
        self, session_lifetime: TimeDelta, session: ServerSideSession, store_id: str
    ) -> None:
        """Update existing or create new session in the session storage."""
        raise NotImplementedError()

    @retry_query()  # use only when retry not supported directly by the client
    def _delete_expired_sessions(self) -> None:
        """Delete expired sessions from the session storage. Only required for non-TTL databases."""
        pass
