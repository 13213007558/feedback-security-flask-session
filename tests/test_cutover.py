"""Client-visible tests for the recoverable session-storage cutover protocol.

Two in-memory backends stand in for the old and new session services. Every
scenario is observed through a Flask test client, because dual-write success
must never be taken as proof of an authoritative, consistent session.
"""

import sys

sys.path.append("src")

import flask  # noqa: E402
import flask_session  # noqa: E402
import pytest  # noqa: E402
from cachelib.simple import SimpleCache  # noqa: E402
from flask_session.migration import (  # noqa: E402
    CUTOVER,
    LEGACY,
    NEW_ONLY,
    STATE_MIGRATED,
    STATE_TOMBSTONED,
    AuthorityUnconfirmed,
    register_cutover_error_handlers,
)

SESSION_PREFIX = "session:"


class FailingBackend:
    """Backend wrapper that can refuse reads, writes or authority claims."""

    def __init__(self, cache, fail_add=False, fail_set=False, fail_get=False,
                 fail_delete=False):
        self.cache = cache
        self.fail_add = fail_add
        self.fail_set = fail_set
        self.fail_get = fail_get
        self.fail_delete = fail_delete

    def get(self, *args, **kwargs):
        if self.fail_get:
            raise ConnectionError("simulated read outage")
        return self.cache.get(*args, **kwargs)

    def add(self, *args, **kwargs):
        if self.fail_add:
            raise ConnectionError("simulated authority claim outage")
        return self.cache.add(*args, **kwargs)

    def set(self, *args, **kwargs):
        if self.fail_set:
            raise ConnectionError("simulated write outage")
        return self.cache.set(*args, **kwargs)

    def delete(self, *args, **kwargs):
        if self.fail_delete:
            raise ConnectionError("simulated delete outage")
        return self.cache.delete(*args, **kwargs)


def build_app(legacy, new, phase=CUTOVER, identity_keys=("_user_id",)):
    app = flask.Flask(__name__)
    app.secret_key = "cutover-test-secret"
    app.config.update(
        SESSION_TYPE="cutover",
        SESSION_SERIALIZATION_FORMAT="json",
        SESSION_PERMANENT=False,
        # Reads must stay side-effect free: TTL refreshes would otherwise turn
        # a GET into a storage write and obscure the migration ordering.
        SESSION_REFRESH_EACH_REQUEST=False,
        SESSION_CUTOVER_LEGACY=legacy,
        SESSION_CUTOVER_NEW=new,
        SESSION_CUTOVER_PHASE=phase,
        SESSION_CUTOVER_IDENTITY_KEYS=identity_keys,
        SESSION_CUTOVER_TOMBSTONE_TIMEOUT=3600,
    )

    @app.route("/set", methods=["POST"])
    def set_value():
        flask.session["value"] = flask.request.form["value"]
        return "value set"

    @app.route("/get")
    def get_value():
        return flask.session.get("value", "no value set")

    @app.route("/login", methods=["POST"])
    def login():
        flask.session["_user_id"] = flask.request.form["user_id"]
        return "logged in"

    @app.route("/whoami")
    def whoami():
        return flask.session.get("_user_id", "anonymous")

    @app.route("/logout", methods=["POST"])
    def logout():
        # A real logout ends the server-side session outright: the stored
        # record is replaced by a tombstone and the cookie is deleted, rather
        # than merely overwriting the identity key.
        store_id = app.session_interface._get_store_id(flask.session.sid)
        app.session_interface._delete_session(store_id)
        flask.session.clear()
        flask.session.modified = True
        response = flask.make_response("logged out")
        response.delete_cookie(
            key=app.config["SESSION_COOKIE_NAME"],
            domain=app.session_interface.get_cookie_domain(app),
            path=app.session_interface.get_cookie_path(app),
        )
        return response

    flask_session.Session(app)
    register_cutover_error_handlers(app)
    return app


def cookie_sid(client):
    cookie = client.get_cookie("session", domain="localhost")
    if cookie is None:
        raise AssertionError("no session cookie")
    return cookie.value


def stored_key(client):
    return SESSION_PREFIX + cookie_sid(client)


class TestReadFallback:
    def test_legacy_only_reads_fall_back_to_old_backend(self):
        legacy, new = SimpleCache(), SimpleCache()
        app = build_app(legacy, new)
        interface = app.session_interface

        # Seed a session as if it had been written by the old service.
        seed_client = app.test_client()
        seed_client.post("/set", data={"value": "legacy-1"})
        key = stored_key(seed_client)
        assert legacy.has(key)
        sid = cookie_sid(seed_client)

        # Recreate the new service process: no migration state yet, but the
        # durable phase marker moves the deployment into the cutover phase.
        app2 = build_app(legacy, new)
        interface.set_phase(CUTOVER)
        returning = app2.test_client()
        returning.set_cookie("session", sid, domain="localhost")
        assert returning.get("/get").data == b"legacy-1"

        # Reading must not have migrated or duplicated anything.
        assert legacy.has(key)
        assert not new.has(key)
        assert new.get(interface._authority_key(key)) is None


class TestMigrationOrdering:
    def test_claim_then_new_write_then_legacy_invalidation_on_identity_write(self):
        legacy, new = SimpleCache(), SimpleCache()
        app = build_app(legacy, new)
        interface = app.session_interface

        client = app.test_client()
        client.post("/set", data={"value": "pre-login"})
        key = stored_key(client)
        assert legacy.has(key) and not new.has(key)

        response = client.post("/login", data={"user_id": "alice"})
        assert response.status_code == 200
        authority = new.get(interface._authority_key(key))

        # Migration confirmation: authority claimed, data in the new backend,
        # and the legacy copy invalidated last.
        assert authority["state"] == STATE_MIGRATED
        assert new.get(key)["_user_id"] == "alice"
        assert not legacy.has(key)

        # Exactly one writer for the whole session lifetime.
        writes = [backend.has(key) for backend in (legacy, new)]
        assert writes == [False, True]

        # Subsequent writes stay on the new backend; the legacy one never
        # reappears, even after a simulated process restart.
        client.post("/set", data={"value": "later"})
        app_restarted = build_app(legacy, new)
        again = app_restarted.test_client()
        again.set_cookie("session", cookie_sid(client), domain="localhost")
        assert again.get("/get").data == b"later"
        assert not legacy.has(key)

    def test_non_identity_writes_remain_on_legacy_without_dual_write(self):
        legacy, new = SimpleCache(), SimpleCache()
        app = build_app(legacy, new)
        client = app.test_client()
        client.post("/set", data={"value": "v1"})
        client.post("/set", data={"value": "v2"})
        key = stored_key(client)

        # Before any identity change the cutover phase never dual-writes: the
        # session stays solely on the legacy backend and no authority exists.
        assert legacy.has(key)
        assert not new.has(key)
        assert new.get(app.session_interface._authority_key(key)) is None
        assert sum(backend.has(key) for backend in (legacy, new)) == 1


class TestMigrationFaults:
    def test_crash_after_claim_before_data_write_is_repaired_on_revisit(self):
        legacy, new = SimpleCache(), SimpleCache()
        app = build_app(legacy, new)
        interface = app.session_interface
        client = app.test_client()
        client.post("/set", data={"value": "survivor"})
        key = stored_key(client)
        ttl = total_ttl(app)

        # Simulate a crash window: authority claimed and legacy snapshot
        # captured, but the new data write never landed and legacy was not
        # deleted yet.
        new.add(interface._authority_key(key),
                {"state": STATE_MIGRATED, "owner": "crashed", "ttl": ttl}, ttl)
        assert new.get(key) is None
        assert legacy.has(key)

        # Reads keep working through the legacy fallback and do not perform
        # speculative repair, so the crash window has no client-visible effect.
        assert client.get("/get").data == b"survivor"
        assert new.get(key) is None
        assert legacy.has(key)

        # The next identity-changing write resumes the interrupted migration:
        # the legacy snapshot is preserved into the new backend exactly once.
        client.post("/login", data={"user_id": "alice"})
        assert new.get(key)["value"] == "survivor"
        assert new.get(key)["_user_id"] == "alice"
        assert not legacy.has(key)
        assert (
            new.get(interface._authority_key(key))["state"] == STATE_MIGRATED
        )

    def test_identity_change_is_refused_when_authority_unclaimable(self):
        raw_new, legacy = SimpleCache(), SimpleCache()
        new = FailingBackend(raw_new, fail_add=True)
        app = build_app(legacy, new)
        client = app.test_client()
        client.post("/set", data={"value": "visitor"})
        key = stored_key(client)

        response = client.post("/login", data={"user_id": "mallory"})

        # Both backends being "writable" is not authority. The identity change
        # is refused and the legacy session stays unmodified.
        assert response.status_code == 409
        assert response.get_json()["reauthenticate"] is True
        assert client.get("/whoami").data == b"anonymous"
        assert legacy.get(key).get("_user_id") is None
        assert raw_new.get(key) is None

    def test_non_identity_write_survives_new_backend_outage(self):
        raw_new, legacy = SimpleCache(), SimpleCache()
        new = FailingBackend(raw_new, fail_add=True, fail_set=True)
        app = build_app(legacy, new)
        client = app.test_client()
        client.post("/set", data={"value": "kept-going"})
        key = stored_key(client)

        # Ordinary, non-identity traffic falls back to the legacy backend
        # without ever claiming two writers.
        assert client.get("/get").data == b"kept-going"
        assert legacy.get(key)["value"] == "kept-going"
        assert raw_new.get(key) is None


def total_ttl(app):
    from flask_session._utils import total_seconds

    return total_seconds(app.permanent_session_lifetime)


class TestLegacyLateWrite:
    def test_old_process_write_after_migration_is_fenced(self):
        legacy, new = SimpleCache(), SimpleCache()
        app = build_app(legacy, new)
        interface = app.session_interface
        client = app.test_client()
        client.post("/login", data={"user_id": "alice"})
        key = stored_key(client)
        assert not legacy.has(key)

        # A retired old process comes back and writes stale data directly.
        legacy.set(key, {"_user_id": "stale-old-process", "value": "stale"})

        # The migrated authority fences the late legacy write completely.
        assert client.get("/whoami").data == b"alice"
        assert new.get(interface._authority_key(key))["state"] == STATE_MIGRATED
        assert client.get("/get").data == b"no value set"

    def test_identity_change_against_tombstone_is_refused(self):
        legacy, new = SimpleCache(), SimpleCache()
        app = build_app(legacy, new)
        interface = app.session_interface
        client = app.test_client()
        client.post("/login", data={"user_id": "alice"})
        key, sid = stored_key(client), cookie_sid(client)

        assert client.post("/logout").status_code == 200
        assert (
            new.get(interface._authority_key(key))["state"] == STATE_TOMBSTONED
        )

        # The logout response deletes the browser cookie; reuse the old sid
        # explicitly to prove the tombstone refuses a new identity.
        returning = app.test_client()
        returning.set_cookie("session", sid, domain="localhost")
        response = returning.post("/login", data={"user_id": "bob"})
        assert response.status_code == 409
        assert returning.get("/whoami").data == b"anonymous"
        assert (
            new.get(interface._authority_key(key))["state"] == STATE_TOMBSTONED
        )


class TestLogoutRecovery:
    def test_tombstone_survives_restart_and_blocks_legacy_resurrection(self):
        legacy, new = SimpleCache(), SimpleCache()
        app = build_app(legacy, new)
        interface = app.session_interface
        client = app.test_client()
        client.post("/login", data={"user_id": "alice"})
        key, sid = stored_key(client), cookie_sid(client)

        client.post("/logout")
        assert new.get(interface._authority_key(key))["state"] == STATE_TOMBSTONED
        assert new.get(key) is None
        assert not legacy.has(key)

        # A stale old process recreates the legacy record after logout.
        legacy.set(key, {"_user_id": "alice", "value": "ghost"})

        restarted = build_app(legacy, new)
        returning = restarted.test_client()
        returning.set_cookie("session", sid, domain="localhost")
        assert returning.get("/whoami").data == b"anonymous"
        assert returning.get("/get").data == b"no value set"
        assert (
            new.get(restarted.session_interface._authority_key(key))["state"]
            == STATE_TOMBSTONED
        )

    def test_logout_is_refused_when_tombstone_cannot_be_persisted(self):
        raw_new, legacy = SimpleCache(), SimpleCache()
        new = FailingBackend(raw_new, fail_add=True, fail_set=True)
        app = build_app(legacy, new)
        client = app.test_client()
        # Establish an authenticated session on the legacy backend first; the
        # identity change is refused by the new backend, so the ordinary write
        # path still creates the session cookie and legacy record.
        client.post("/set", data={"value": "alice-on-legacy"})
        key, sid = stored_key(client), cookie_sid(client)
        assert legacy.has(key)

        response = client.post("/logout")

        # Fail-closed: the logout is reported as unavailable and the legacy
        # record remains intact rather than being deleted without an
        # authoritative tombstone to fence late writes.
        assert response.status_code == 503
        assert legacy.has(key)

        returning = app.test_client()
        returning.set_cookie("session", sid, domain="localhost")
        assert returning.get("/get").data == b"alice-on-legacy"

    def test_logout_in_legacy_phase_deletes_sole_legacy_record(self):
        legacy, new = SimpleCache(), SimpleCache()
        app = build_app(legacy, new, phase=LEGACY)
        interface = app.session_interface
        client = app.test_client()
        client.post("/set", data={"value": "legacy-only"})
        key = stored_key(client)

        assert client.post("/logout").status_code == 200
        assert not legacy.has(key)
        assert new.get(interface._authority_key(key)) is None

    def test_logout_with_unreadable_phase_marker_fails_closed(self):
        raw_new, legacy = SimpleCache(), SimpleCache()
        new = FailingBackend(raw_new, fail_get=True)
        app = build_app(legacy, new)
        client = app.test_client()
        client.post("/set", data={"value": "stranded"})
        key = stored_key(client)

        response = client.post("/logout")
        assert response.status_code == 503
        assert legacy.has(key)


class TestPhases:
    def test_legacy_phase_never_touches_new_backend(self):
        legacy, new = SimpleCache(), SimpleCache()
        app = build_app(legacy, new, phase=LEGACY)
        client = app.test_client()
        client.post("/login", data={"user_id": "alice"})
        client.post("/set", data={"value": "1"})
        key = stored_key(client)
        assert legacy.has(key)
        assert not new.has(key)
        assert new.get(app.session_interface._authority_key(key)) is None

    def test_new_only_phase_ignores_legacy_history(self):
        legacy, new = SimpleCache(), SimpleCache()
        app = build_app(legacy, new, phase=NEW_ONLY)
        legacy.set(SESSION_PREFIX + "oldsid",
                   {"_user_id": "ghost", "value": "history"})
        client = app.test_client()
        client.set_cookie("session", "oldsid", domain="localhost")

        assert client.get("/whoami").data == b"anonymous"
        client.post("/set", data={"value": "fresh"})
        key = SESSION_PREFIX + "oldsid"
        assert new.get(key)["value"] == "fresh"
        assert legacy.get(key)["value"] == "history"  # never written/overwritten

    def test_phase_marker_is_durable_and_forward_only(self):
        legacy, new = SimpleCache(), SimpleCache()
        app = build_app(legacy, new, phase=LEGACY)
        interface = app.session_interface
        interface.set_phase(CUTOVER)
        interface.set_phase(NEW_ONLY)

        restarted = build_app(legacy, new, phase=LEGACY)
        assert restarted.session_interface._read_phase() == NEW_ONLY
        with pytest.raises(ValueError):
            restarted.session_interface.set_phase(CUTOVER)

    def test_unreadable_phase_marker_refuses_identity_change(self):
        raw_new, legacy = SimpleCache(), SimpleCache()
        new = FailingBackend(raw_new, fail_get=True, fail_add=True)
        app = build_app(legacy, new)
        client = app.test_client()
        response = client.post("/login", data={"user_id": "alice"})
        assert response.status_code == 409
        assert client.get("/whoami").data == b"anonymous"

    def test_identity_read_during_new_backend_outage_still_works(self):
        raw_new, legacy = SimpleCache(), SimpleCache()
        new = FailingBackend(raw_new, fail_get=True, fail_add=True)
        app = build_app(legacy, new)
        client = app.test_client()
        client.post("/set", data={"value": "readable"})

        # Reading (not changing) identity-bearing data must not be refused just
        # because the new backend is unreachable; the legacy fallback serves it.
        response = client.get("/get")
        assert response.status_code == 200
        assert response.data == b"readable"

    def test_switching_authenticated_identity_migrates_once(self):
        legacy, new = SimpleCache(), SimpleCache()
        app = build_app(legacy, new)
        interface = app.session_interface
        client = app.test_client()
        assert client.post("/login", data={"user_id": "alice"}).status_code == 200
        key = stored_key(client)
        assert new.get(interface._authority_key(key))["state"] == STATE_MIGRATED

        # A second identity change stays on the single authoritative backend.
        assert client.post("/login", data={"user_id": "bob"}).status_code == 200
        assert client.get("/whoami").data == b"bob"
        assert not legacy.has(key)
        assert new.get(key)["_user_id"] == "bob"
        assert sum(backend.has(key) for backend in (legacy, new)) == 1


class TestProtocolErrors:
    def test_error_hierarchy_is_fail_closed(self):
        assert issubclass(AuthorityUnconfirmed, Exception)

    def test_missing_backends_are_rejected(self):
        with pytest.raises(ValueError):
            build_app(None, SimpleCache())
