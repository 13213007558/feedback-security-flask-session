import pickle
import pickletools
import random
import secrets
import warnings
from abc import ABC, abstractmethod
from datetime import timedelta as TimeDelta
from typing import Any, Callable, Dict, Optional

import msgspec
from flask import Flask, Request, Response
from flask.sessions import SessionInterface as FlaskSessionInterface
from flask.sessions import SessionMixin
from itsdangerous import BadSignature, Signer, want_bytes
from werkzeug.datastructures import CallbackDict

from ._utils import retry_query
from .defaults import Defaults


class SessionDeserializationError(pickle.UnpicklingError):
    """Raised when stored session data cannot be read using an approved format."""


# Legacy pickle records may only contain the plain container and scalar types
# produced by ``pickle.dumps(dict(session))``. An allowlist is used so opcodes
# that can import names, call code, or restore persistent objects are rejected
# before the legacy decoder is invoked.
_SAFE_LEGACY_PICKLE_OPCODES = frozenset(
    {
        "PROTO",
        "FRAME",
        "STOP",
        "MARK",
        "POP",
        "POP_MARK",
        "DUP",
        "GET",
        "BINGET",
        "LONG_BINGET",
        "PUT",
        "BINPUT",
        "LONG_BINPUT",
        "MEMOIZE",
        "EMPTY_DICT",
        "DICT",
        "SETITEM",
        "SETITEMS",
        "EMPTY_LIST",
        "APPEND",
        "APPENDS",
        "EMPTY_TUPLE",
        "TUPLE",
        "TUPLE1",
        "TUPLE2",
        "TUPLE3",
        "EMPTY_SET",
        "ADDITEMS",
        "FROZENSET",
        "NONE",
        "NEWTRUE",
        "NEWFALSE",
        "INT",
        "BININT",
        "BININT1",
        "BININT2",
        "LONG",
        "LONG1",
        "LONG4",
        "FLOAT",
        "BINFLOAT",
        "STRING",
        "BINSTRING",
        "SHORT_BINSTRING",
        "BINBYTES",
        "SHORT_BINBYTES",
        "BINBYTES8",
        "BYTEARRAY8",
        "UNICODE",
        "SHORT_BINUNICODE",
        "BINUNICODE",
        "BINUNICODE8",
    }
)


def _is_safe_legacy_pickle(serialized_data: bytes) -> bool:
    """Return whether ``serialized_data`` is an inert pickle of plain data.

    The check uses :mod:`pickletools`, which parses opcodes without executing
    them. It intentionally is not a general-purpose pickle allowlist: only the
    shape written by Flask-Session's historical ``dict(session)`` records is
    accepted.
    """
    if not serialized_data:
        return False

    saw_stop = False
    saw_dict = False
    last_position = 0
    try:
        for opcode, _argument, position in pickletools.genops(serialized_data):
            if opcode.name not in _SAFE_LEGACY_PICKLE_OPCODES:
                return False
            if opcode.name in {"EMPTY_DICT", "DICT"}:
                saw_dict = True
            last_position = position
            if opcode.name == "STOP":
                saw_stop = True
                break
    except Exception:
        return False

    if not (saw_stop and saw_dict):
        return False

    # ``pickletools.genops`` stops at the first STOP and does not report
    # trailing bytes. ``pickle.loads`` also ignores them, so reject any payload
    # with extra data instead of silently trusting a truncated prefix.
    stop_opcode_length = 1  # len(".")
    return last_position + stop_opcode_length >= len(serialized_data)


def _default_legacy_pickle_decoder(serialized_data: bytes) -> Any:
    # Kept as a module-level indirection so callers and tests can observe or
    # replace the legacy decoder without changing any other decoding path.
    return pickle.loads(serialized_data)


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
    def __init__(
        self,
        app: Flask,
        format: str,
        allow_pickle_fallback: Optional[bool] = None,
        legacy_decoder: Optional[Callable[[bytes], Any]] = None,
    ):
        self.app: Flask = app
        self.encoder: msgspec.msgpack.Encoder or msgspec.json.Encoder
        self.decoder: msgspec.msgpack.Decoder or msgspec.json.Decoder
        self.alternate_decoder: msgspec.msgpack.Decoder or msgspec.json.Decoder
        if allow_pickle_fallback is None:
            allow_pickle_fallback = Defaults.SESSION_ALLOW_PICKLE_FALLBACK
            if app is not None:
                allow_pickle_fallback = app.config.get(
                    "SESSION_ALLOW_PICKLE_FALLBACK", allow_pickle_fallback
                )
        self.allow_pickle_fallback = allow_pickle_fallback
        self.legacy_decoder = legacy_decoder or _default_legacy_pickle_decoder

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
        """Deserialize stored session data using only approved formats.

        Safe formats are attempted in order. Legacy pickle data is considered
        only when ``allow_pickle_fallback`` was explicitly enabled, and only
        after the payload has been verified to be an inert plain-data pickle.
        A payload that reaches the legacy step is never retried with a safe
        decoder afterward.
        """
        try:
            decoded = self.decoder.decode(serialized_data)
        except msgspec.DecodeError:
            decoded = None
        if isinstance(decoded, dict):
            return decoded

        try:
            decoded = self.alternate_decoder.decode(serialized_data)
        except msgspec.DecodeError:
            decoded = None
        if isinstance(decoded, dict):
            return decoded

        # Only a structurally verified plain-dict pickle may reach the legacy
        # decoder. The verification itself never executes the payload.
        if self.allow_pickle_fallback and _is_safe_legacy_pickle(serialized_data):
            try:
                decoded = self.legacy_decoder(serialized_data)
            except Exception:
                self.app.logger.warning(
                    "Failed to decode an approved legacy pickle session record.",
                    exc_info=True,
                )
                decoded = None
            if isinstance(decoded, dict):
                return decoded

        self.app.logger.error("Failed to deserialize session data")
        raise SessionDeserializationError("Failed to deserialize session data")


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
        allow_pickle_fallback: Optional[bool] = None,
        legacy_decoder: Optional[Callable[[bytes], Any]] = None,
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
        self.serializer = MsgSpecSerializer(
            format=serialization_format,
            app=app,
            allow_pickle_fallback=allow_pickle_fallback,
            legacy_decoder=legacy_decoder,
        )

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
        """Open a session, failing safely when stored data is unreadable.

        An unreadable stored value yields a fresh session with a new id. The
        stored record is not deleted, so an operator can inspect or migrate it
        offline. This also prevents a concurrent read from silently treating
        the corrupt session as empty.
        """
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
        try:
            saved_session_data = self._retrieve_session_data(store_id)
        except SessionDeserializationError:
            saved_session_data = None

        # If the saved session exists, load the session data from the document
        if not isinstance(saved_session_data, dict):
            if saved_session_data is not None:
                app.logger.warning(
                    "Ignoring unreadable session data for %s; the stored "
                    "record was left in place for offline migration.",
                    store_id,
                )
            sid = self._generate_sid(self.sid_length)
            return self.session_class(sid=sid, permanent=self.permanent)

        return self.session_class(saved_session_data, sid=sid)

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
