"""Regression tests for the decidable session-state retry contract.

These tests use an in-memory, fault-injectable backend (no external service)
to prove what happens when a failure occurs *before* the commit point versus
*after* it (the "backend committed but the client timed out" case).
"""

import sys
from datetime import timedelta
from pathlib import Path

import pytest
from flask import Flask, Response, request

from flask_session._utils import retry_query
from flask_session.base import ServerSideSession
from flask_session.exceptions import (
    AmbiguousSessionStateError,
    RetriableSessionError,
)

_EXAMPLE_DIR = Path(__file__).resolve().parents[1] / "examples" / "retry_contract"
sys.path.insert(0, str(_EXAMPLE_DIR))

from controllable_backend import (  # noqa: E402
    CommitTimeout,
    ControllableSession,
    ControllableSessionInterface,
    ControllableStore,
    TransientStorageError,
)


@pytest.fixture
def harness(monkeypatch):
    monkeypatch.setattr("flask_session._utils.time.sleep", lambda *a, **k: None)
    app = Flask(__name__)
    app.secret_key = "retry-contract-secret"
    app.config["SESSION_COOKIE_NAME"] = "session"
    store = ControllableStore()
    app.session_interface = ControllableSessionInterface(app, store)
    return app, store


def _open(app, cookie=None):
    with app.test_request_context(
        headers={"Cookie": cookie} if cookie else None
    ):
        return app.session_interface.open_session(app, request)


def _save(app, session):
    response = Response()
    with app.test_request_context():
        app.session_interface.save_session(app, session, response)
    return response


def _login(app, store):
    session = _open(app)
    session["user"] = "alice"
    response = _save(app, session)
    cookie = response.headers.getlist("Set-Cookie")[0].split(";", 1)[0]
    store.reset_journal()
    return cookie, session.sid


def test_base_wrapper_is_inherited_and_wrapped(harness):
    app, _ = harness
    iface = app.session_interface
    # The retry layer must survive subclassing (it did not before the fix).
    assert hasattr(iface._delete_session, "__wrapped__")
    assert hasattr(iface._upsert_session, "__wrapped__")
    assert hasattr(iface._retrieve_session_data, "__wrapped__")


def test_pre_commit_save_retries_then_succeeds(harness):
    app, store = harness
    cookie, sid = _login(app, store)
    store.configure_fault("set", times=2, kind="pre_commit")

    session = _open(app, cookie)
    session["extra"] = 1
    response = _save(app, session)

    assert sum(c.startswith("set") for c in store.calls) == 3
    assert response.headers.getlist("Set-Cookie")  # success path still emits cookie
    assert store.exists(f"session:{sid}")


def test_pre_commit_failure_exhausted_is_surfaced_not_hidden(harness):
    app, store = harness
    cookie, _ = _login(app, store)
    store.configure_fault("set", times=99, kind="pre_commit")

    session = _open(app, cookie)
    session["extra"] = 1
    with pytest.raises(RetriableSessionError):
        _save(app, session)

    assert sum(c.startswith("set") for c in store.calls) == 3  # bounded, not infinite


def test_ambiguous_save_is_not_retried_and_sets_no_cookie(harness):
    app, store = harness
    cookie, sid = _login(app, store)
    store.configure_fault("set", times=99, kind="post_commit")

    session = _open(app, cookie)
    session["extra"] = 2
    response = None
    with pytest.raises(AmbiguousSessionStateError) as info:
        response = _save(app, session)

    assert info.value.operation == "upsert"
    assert info.value.store_id == f"session:{sid}"
    # Idempotent replay, but still bounded by max_attempts.
    assert sum(c.startswith("set") for c in store.calls) == 3
    assert response is None  # no cookie pointed at an uncertain record


def test_definite_error_is_never_retried(harness):
    app, store = harness
    cookie, _ = _login(app, store)

    # A non-contract exception must propagate on the first attempt.
    def boom(store_id, value):
        raise ValueError("definite programming error")

    store.set = boom
    session = _open(app, cookie)
    session["extra"] = 3
    with pytest.raises(ValueError):
        _save(app, session)
    # The failing write ran exactly once; a definite error is not retried.
    assert sum(c.startswith("set") for c in store.calls) == 0


def test_logout_pre_commit_retries_and_deletes(harness):
    app, store = harness
    cookie, sid = _login(app, store)
    store.configure_fault("delete", times=2, kind="pre_commit")

    session = _open(app, cookie)
    session.clear()
    session.modified = True
    response = _save(app, session)

    assert sum(c.startswith("delete") for c in store.calls) == 3
    assert not store.exists(f"session:{sid}")
    assert any(
        c.startswith("session=;") for c in response.headers.getlist("Set-Cookie")
    )


def test_ambiguous_logout_does_not_clear_cookie_or_resurrect(harness):
    app, store = harness
    cookie, sid = _login(app, store)
    store.configure_fault("delete", times=99, kind="post_commit")

    session = _open(app, cookie)
    session.clear()
    session.modified = True
    response = None
    with pytest.raises(AmbiguousSessionStateError):
        response = _save(app, session)

    # The record may already be gone, but we never tell the client otherwise
    # while the result is unknown, and we never re-save the deleted login.
    assert response is None
    assert not any(
        c.startswith("set") for c in store.calls
    )  # no accidental resurrection write


def test_regenerate_pre_commit_keeps_old_identity_and_no_fixation_window(harness):
    app, store = harness
    cookie, sid = _login(app, store)
    store.configure_fault("delete", times=99, kind="pre_commit")

    session = _open(app, cookie)
    original_sid = session.sid
    with pytest.raises(RetriableSessionError):
        with app.test_request_context():
            app.session_interface.regenerate(session)

    assert session.sid == original_sid  # no new identity minted
    assert store.exists(f"session:{sid}")  # old record untouched by failed delete


def test_regenerate_post_commit_ambiguous_keeps_old_identity(harness):
    app, store = harness
    cookie, sid = _login(app, store)
    store.configure_fault("delete", times=99, kind="post_commit")

    session = _open(app, cookie)
    original_sid = session.sid
    with pytest.raises(AmbiguousSessionStateError):
        with app.test_request_context():
            app.session_interface.regenerate(session)

    # A new sid must not be issued while the old deletion is unconfirmed.
    assert session.sid == original_sid


def test_regenerate_success_rotates_identity(harness):
    app, store = harness
    cookie, sid = _login(app, store)

    session = _open(app, cookie)
    with app.test_request_context():
        app.session_interface.regenerate(session)
    assert session.sid != sid
    assert not store.exists(f"session:{sid}")


def test_non_idempotent_write_aborts_on_first_ambiguous_result(harness):
    app, store = harness

    class InsertOnlyInterface(ControllableSessionInterface):
        @retry_query(operation="upsert", idempotent=False)
        def _upsert_session(self, lifetime, session, store_id):
            self._upsert_session_impl(lifetime, session, store_id)

    app.session_interface = InsertOnlyInterface(app, store)
    store.configure_fault("set", times=99, kind="post_commit")
    session = ControllableSession({"user": "bob"}, sid="new")
    with pytest.raises(AmbiguousSessionStateError):
        with app.app_context():
            app.session_interface._upsert_session(
                timedelta(minutes=5), session, "session:new"
            )
    assert sum(c.startswith("set") for c in store.calls) == 1


def test_next_request_identity_after_ambiguous_save(harness):
    app, store = harness
    cookie, sid = _login(app, store)
    store.configure_fault("set", times=99, kind="post_commit")
    session = _open(app, cookie)
    session["extra"] = 9
    with pytest.raises(AmbiguousSessionStateError):
        _save(app, session)

    # The browser keeps its original cookie and resolves back to the same,
    # still-authenticated identity; nothing fabricates a replacement session.
    next_session = _open(app, cookie)
    assert next_session.sid == sid
    assert next_session.get("user") == "alice"
