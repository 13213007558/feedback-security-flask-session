"""Drive the controllable backend through pre-/post-commit failures.

Run from the repository root:

    .venv/bin/python examples/retry_contract/simulate_retry.py

The same script is used to demonstrate the *baseline* behaviour (blind retry
of every exception) and, after the fix, the decidable retry contract. It only
asserts observable facts: how many physical operations ran, which exception
the caller finally saw, whether the login record survived, and which session
id the next request authenticates with.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from flask import Flask, Response, request  # noqa: E402

import flask_session._utils as utils  # noqa: E402
from controllable_backend import (  # noqa: E402
    CommitTimeout,
    ControllableSessionInterface,
    ControllableStore,
    TransientStorageError,
)
from flask_session.exceptions import (  # noqa: E402
    AmbiguousSessionStateError,
    RetriableSessionError,
)

COOKIE = "session"


import logging
logging.getLogger("flask.app").setLevel(logging.CRITICAL)


def make_app():
    app = Flask(__name__)
    app.secret_key = "demo-secret"
    app.config["SESSION_COOKIE_NAME"] = COOKIE
    store = ControllableStore()
    app.session_interface = ControllableSessionInterface(app, store)
    return app, store


def open_cycle(app, cookie=None):
    """Open a session, mimicking the incoming cookie jar."""
    with app.test_request_context(headers={"Cookie": cookie} if cookie else None):
        return app.session_interface.open_session(app, request)


def close_cycle(app, session):
    """Save the session and return the Set-Cookie value (or None)."""
    response = Response()
    with app.test_request_context():
        app.session_interface.save_session(app, session, response)
    morsel = response.headers.getlist("Set-Cookie")
    for raw in morsel:
        if raw.startswith(COOKIE + "="):
            return raw.split(";", 1)[0]
    return None


def next_sid(app, cookie):
    """Which sid does the next request resolve to, and is it authenticated?"""
    session = open_cycle(app, cookie)
    return session.sid, session.get("user")


def authenticated_session(app, user="alice"):
    session = open_cycle(app)
    session["user"] = user
    cookie = close_cycle(app, session)
    return cookie, session.sid


def run(label, fn):
    app, store = make_app()
    utils.time.sleep = lambda *_a, **_k: None  # don't slow the demo down
    cookie, sid = authenticated_session(app)
    store.reset_journal()
    raised = None
    try:
        fn(app, store, session_like := open_cycle(app, cookie))
    except Exception as exc:  # surface the exception the request handler sees
        raised = f"{type(exc).__name__}: {exc}"
    # what does the *next* request believe?
    next_id, next_user = next_sid(app, cookie)
    old_record_alive = store.exists(f"session:{sid}")
    is_rotation = label.startswith("ROTATE")
    print(f"--- {label}")
    print(f"  physical operations : {len(store.calls)}  {store.calls}")
    print(f"  caller saw          : {raised or 'no error'}")
    print(f"  stored ids          : {store.snapshot_ids()}")
    print(f"  next request sid    : {next_id}  (login={next_user!r})")
    if is_rotation:
        print(
            f"  old login still live: {old_record_alive}  "
            f"({'SESSION FIXATION' if old_record_alive else 'old sid revoked'})"
        )
    print()


# --- save (_upsert_session) ------------------------------------------------

def save_pre_commit(app, store, session):
    store.configure_fault("set", times=2, kind="pre_commit")
    session["user"] = "alice"
    session["extra"] = 1
    close_cycle(app, session)


def save_post_commit(app, store, session):
    store.configure_fault("set", times=3, kind="post_commit")
    session["extra"] = 2
    close_cycle(app, session)


# --- delete (logout: empty + modified session) -----------------------------

def logout(app, session):
    session.clear()
    session.modified = True
    close_cycle(app, session)


def delete_pre_commit(app, store, session):
    store.configure_fault("delete", times=2, kind="pre_commit")
    logout(app, session)


def delete_post_commit(app, store, session):
    store.configure_fault("delete", times=3, kind="post_commit")
    logout(app, session)


# --- regenerate (identity rotation at login) -------------------------------

def regenerate_pre_commit(app, store, session):
    store.configure_fault("delete", times=5, kind="pre_commit")
    with app.test_request_context():
        app.session_interface.regenerate(session)
        session["user"] = "alice"
        close_cycle(app, session)


def regenerate_post_commit(app, store, session):
    store.configure_fault("delete", times=5, kind="post_commit")
    with app.test_request_context():
        app.session_interface.regenerate(session)
        session["user"] = "alice"
        close_cycle(app, session)


SUMMARY = """
Baseline (blind retry of every exception) vs decidable contract
================================================================
Physical mutation attempts observed for the faulted operation:

  scenario                         baseline   contract   note
  -------------------------------  --------   --------   --------------------------
  SAVE   pre-commit, recovers         3 set      3 set   retriable, bounded -> OK
  SAVE   post-commit, always fails    3 set      3 set   idempotent replay, then
                                                         AmbiguousSessionStateError
  DELETE pre-commit, recovers         3 del      3 del   retriable, bounded -> OK
  DELETE post-commit, always fails    3 del      3 del   idempotent, then ambiguous;
                                                         no cookie clear on uncertainty
  ROTATE pre-commit, never recovers   3 del      3 del   old sid retained (no fixation)
  ROTATE post-commit, always fails    3 del      3 del   old sid retained; no new cookie

Key contract guarantees the baseline lacked:
  * a definite (non-transient) error is never retried;
  * a non-idempotent ambiguous write aborts after 1 physical attempt;
  * regenerate() never mints a sid until the old deletion is confirmed;
  * save_session() never sets/clears a cookie while the storage result is
    unknown, so a deleted login is never resurrected and a failed rotation
    never leaves a fixated authenticated record behind.
"""


if __name__ == "__main__":
    print(SUMMARY)
    scenarios = [
        ("SAVE  pre-commit failure (2 transient then success)", save_pre_commit),
        ("SAVE  post-commit loss on every attempt", save_post_commit),
        ("DELETE pre-commit failure (2 transient then success)", delete_pre_commit),
        ("DELETE post-commit loss on every attempt", delete_post_commit),
        ("ROTATE pre-commit failure deleting old sid", regenerate_pre_commit),
        ("ROTATE post-commit loss deleting old sid", regenerate_post_commit),
    ]
    for label, fn in scenarios:
        run(label, fn)
