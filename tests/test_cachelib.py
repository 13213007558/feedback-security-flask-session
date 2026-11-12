import os
import shutil
from contextlib import contextmanager

import flask
import pytest
from cachelib.file import FileSystemCache
from cachelib.simple import SimpleCache
from flask_session.base import SessionRegenerationError
from flask_session.cachelib import CacheLibSession


class TestCachelibSession:
    session_dir = "testing_session_storage"

    @contextmanager
    def setup_filesystem(self):
        try:
            yield
        finally:
            pass
            if self.session_dir and os.path.isdir(self.session_dir):
                shutil.rmtree(self.session_dir)

    def retrieve_stored_session(self, key, app):
        return app.session_interface.cache.get(key)

    def test_filesystem_default(self, app_utils):
        app = app_utils.create_app(
            {
                "SESSION_TYPE": "cachelib",
                "SESSION_SERIALIZATION_FORMAT": "json",
                "SESSION_CACHELIB": FileSystemCache(
                    threshold=500, cache_dir=self.session_dir
                ),
            }
        )

        # Should be using CacheLib (FileSystem)
        with self.setup_filesystem(), app.test_request_context():
            assert isinstance(
                flask.session,
                CacheLibSession,
            )
            app_utils.test_session(app)

            # Check if the session is stored in the filesystem
            cookie = app_utils.test_session_with_cookie(app)
            session_id = cookie.split(";")[0].split("=")[1]
            stored_session = self.retrieve_stored_session(f"session:{session_id}", app)
            assert stored_session.get("value") == "44"


def create_regeneration_app(app_utils, cache=None):
    app = app_utils.create_app(
        {
            "SESSION_TYPE": "cachelib",
            "SESSION_SERIALIZATION_FORMAT": "json",
            "SESSION_CACHELIB": cache or SimpleCache(),
        }
    )

    @app.route("/anon-set")
    def anon_set():
        flask.session["anonymous"] = "visitor"
        return str(flask.session.sid)

    @app.route("/login", methods=["POST"])
    def login():
        # Mimic a login flow that clears anonymous data, rotates the id, then
        # writes the authenticated identity.
        sid_before = flask.session.sid
        flask.session.clear()
        app.session_interface.regenerate(flask.session)
        sid_after = flask.session.sid
        if flask.request.form.get("fail_auth") == "1":
            flask.session.clear()
            return f"{sid_before} {sid_after} login failed", 401
        flask.session["user_id"] = flask.request.form["user_id"]
        return f"{sid_before} {sid_after} logged in"

    @app.route("/whoami")
    def whoami():
        return str(flask.session.get("user_id", "anonymous"))

    @app.route("/rotate-twice")
    def rotate_twice():
        sid_before = flask.session.sid
        app.session_interface.regenerate(flask.session)
        sid_after_first = flask.session.sid
        app.session_interface.regenerate(flask.session)
        sid_after_second = flask.session.sid
        flask.session["rotated"] = True
        return f"{sid_before} {sid_after_first} {sid_after_second}"

    return app


class FailingDeleteCache(SimpleCache):
    def __init__(self):
        super().__init__()
        self.fail_delete = False
        self.ignore_delete = False

    def delete(self, key):
        if self.fail_delete:
            return False
        if self.ignore_delete:
            return True
        return super().delete(key)


def cookie_sid(response):
    for header in response.headers.getlist("Set-Cookie"):
        if header.startswith("session="):
            return header.split(";")[0].split("=", 1)[1]
    return None


def test_regenerate_empty_session_gets_new_sid(app_utils):
    app = create_regeneration_app(app_utils)
    client = app.test_client()

    # The session is empty at the time of rotation, but it still has a sid and
    # must receive a different one before the identity is written.
    response = client.post("/login", data={"user_id": "alice"})
    sid_before, sid_after, _ = response.data.decode().split(" ", 2)
    assert sid_before != sid_after
    assert cookie_sid(response) == sid_after
    assert response.status_code == 200

    assert client.get("/whoami").data == b"alice"
    assert app.session_interface.cache.get(f"session:{sid_after}")["user_id"] == (
        "alice"
    )


def test_regenerate_with_anonymous_record_removes_it(app_utils):
    app = create_regeneration_app(app_utils)
    client = app.test_client()

    anon_response = client.get("/anon-set")
    anon_sid = cookie_sid(anon_response)
    assert app.session_interface.cache.get(f"session:{anon_sid}")["anonymous"] == (
        "visitor"
    )

    # Now the session is cleared and rotated while empty. The previous
    # anonymous record must still be removed.
    response = client.post("/login", data={"user_id": "alice"})
    sid_before, sid_after, _ = response.data.decode().split(" ", 2)
    assert sid_before == anon_sid
    assert sid_after != anon_sid
    assert app.session_interface.cache.get(f"session:{anon_sid}") is None
    assert app.session_interface.cache.get(f"session:{sid_after}")["user_id"] == (
        "alice"
    )

    # The old sid cannot load the new identity.
    client.set_cookie("session", anon_sid)
    assert client.get("/whoami").data == b"anonymous"
    client.set_cookie("session", sid_after)
    assert client.get("/whoami").data == b"alice"


def test_failed_login_does_not_expose_new_identity(app_utils):
    app = create_regeneration_app(app_utils)
    client = app.test_client()

    response = client.post("/login", data={"user_id": "alice"})
    alice_sid = cookie_sid(response)
    assert app.session_interface.cache.get(f"session:{alice_sid}")["user_id"] == (
        "alice"
    )

    response = client.post("/login", data={"user_id": "mallory", "fail_auth": "1"})
    assert response.status_code == 401
    sid_before, failed_sid, _ = response.data.decode().split(" ", 2)
    assert sid_before == alice_sid
    assert failed_sid != alice_sid
    issued_sid = cookie_sid(response)
    # A failed login may bind the client to a fresh, empty id, but never to the
    # old id or to one carrying an identity.
    assert issued_sid in (None, "", failed_sid)
    assert app.session_interface.cache.get(f"session:{alice_sid}") is None
    failed_record = app.session_interface.cache.get(f"session:{failed_sid}")
    assert failed_record is None or "user_id" not in failed_record

    for sid in (alice_sid, failed_sid):
        client.set_cookie("session", sid)
        assert client.get("/whoami").data == b"anonymous"


def test_regenerate_reports_delete_failure(app_utils):
    cache = FailingDeleteCache()
    app = create_regeneration_app(app_utils, cache=cache)
    client = app.test_client()

    response = client.post("/login", data={"user_id": "alice"})
    previous_sid = cookie_sid(response)
    cache.fail_delete = True

    response = client.post("/login", data={"user_id": "bob"})
    assert response.status_code == 500
    assert cookie_sid(response) in (None, "")
    # The old record remains, it was never erased on a refused delete.
    assert cache.get(f"session:{previous_sid}")["user_id"] == "alice"

    # No new identity can be loaded from the old cookie, and the failed
    # rotation did not leave a second valid record behind.
    client.set_cookie("session", previous_sid)
    assert client.get("/whoami").data == b"alice"
    for key in cache._cache:
        assert key == f"session:{previous_sid}"


def test_regenerate_verifies_deleted_record(app_utils):
    cache = FailingDeleteCache()
    app = create_regeneration_app(app_utils, cache=cache)
    client = app.test_client()

    response = client.post("/login", data={"user_id": "alice"})
    previous_sid = cookie_sid(response)
    cache.ignore_delete = True

    response = client.post("/login", data={"user_id": "bob"})
    assert response.status_code == 500
    assert cookie_sid(response) in (None, "")
    assert cache.get(f"session:{previous_sid}")["user_id"] == "alice"

    # An ignored delete result must not be treated as a completed rotation.
    client.set_cookie("session", previous_sid)
    assert client.get("/whoami").data == b"alice"
    assert len(cache._cache) == 1


def test_regenerate_twice_removes_every_old_record(app_utils):
    app = create_regeneration_app(app_utils)
    client = app.test_client()

    response = client.get("/anon-set")
    first_sid = cookie_sid(response)

    response = client.get("/rotate-twice")
    sids = response.data.decode().split(" ")
    assert len(sids) == 3
    assert sids[0] == first_sid
    assert len(set(sids)) == 3
    assert cookie_sid(response) == sids[2]

    cache = app.session_interface.cache
    # The first id's record is removed; the intermediate id was never
    # persisted; only the final id remains usable.
    assert cache.get(f"session:{sids[0]}") is None
    assert cache.get(f"session:{sids[1]}") is None
    assert cache.get(f"session:{sids[2]}")["rotated"] is True

    client.set_cookie("session", sids[0])
    assert client.get("/whoami").data == b"anonymous"
    client.set_cookie("session", sids[1])
    assert client.get("/whoami").data == b"anonymous"
    client.set_cookie("session", sids[2])
    assert client.get("/whoami").data == b"anonymous"


def test_regenerate_rejects_fixated_attacker_record(app_utils):
    app = create_regeneration_app(app_utils)
    client = app.test_client()

    # An attacker can plant a session id and even a server-side record before
    # the victim authenticates.
    fixated_sid = "known-to-the-attacker"
    app.session_interface.cache.set(
        f"session:{fixated_sid}", {"planted": True}
    )
    client.set_cookie("session", fixated_sid)

    response = client.post("/login", data={"user_id": "victim"})
    sid_before, sid_after, _ = response.data.decode().split(" ", 2)
    assert sid_before == fixated_sid
    assert sid_after != fixated_sid
    assert cookie_sid(response) == sid_after

    # The attacker's planted record and the old id are gone.
    client.set_cookie("session", fixated_sid)
    assert client.get("/whoami").data == b"anonymous"
    assert app.session_interface.cache.get(f"session:{fixated_sid}") is None
    assert app.session_interface.cache.get(f"session:{sid_after}")["user_id"] == (
        "victim"
    )


def test_regenerate_delete_success_save_failure_drops_both_records(app_utils):
    cache = FailingDeleteCache()
    app = create_regeneration_app(app_utils, cache=cache)
    client = app.test_client()

    response = client.post("/login", data={"user_id": "alice"})
    old_sid = cookie_sid(response)
    assert cache.get(f"session:{old_sid}")["user_id"] == "alice"

    # The old record is deleted, but saving the newly rotated session fails.
    # This is the window between deletion and the new record being stored.
    original_set = cache.set
    cache.set = lambda key, value, timeout=None: False
    try:
        response = client.post("/login", data={"user_id": "bob"})
    finally:
        cache.set = original_set

    assert response.status_code == 500
    assert cookie_sid(response) in (None, "")
    assert cache.get(f"session:{old_sid}") is None

    # Neither the old SID nor any SID issued in the response can read bob.
    client.set_cookie("session", old_sid)
    assert client.get("/whoami").data == b"anonymous"
    for header in response.headers.getlist("Set-Cookie"):
        sid = header.split(";")[0].split("=", 1)[1]
        if not sid:
            continue
        client.set_cookie("session", sid)
        assert client.get("/whoami").data == b"anonymous"


def test_regenerate_without_sid_is_explicit(app_utils):
    app = create_regeneration_app(app_utils)
    session = app.session_interface.session_class()
    with pytest.raises(SessionRegenerationError):
        app.session_interface.regenerate(session)
    assert session.sid is None
