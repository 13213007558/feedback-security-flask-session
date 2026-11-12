import os
import shutil

import flask
import pytest
from cachelib.file import FileSystemCache
from flask_session import ProtectedFieldError, Session
from flask_session._protected import ProtectedDict, ProtectedList, ProtectedSet
from flask_session.base import ServerSideSession

PROTECTED = {
    "user_id": "auth",
    "auth_level": ["auth", "mfa"],
    "profile": "auth",
}


def exact_type(value, cls):
    """Strict type check (excludes subclasses such as the guarded containers)."""
    return type(value) is cls


def make_session(initial=None):
    return ServerSideSession(initial=initial, sid="sid", protected_fields=PROTECTED)


class TestOrdinaryFieldsUnchanged:
    def test_no_policy_is_plain_dict(self):
        session = ServerSideSession(initial={"a": 1})
        assert session.is_protected("a") is False
        session["a"] = 2
        session["b"] = 3
        session.update({"c": 4})
        assert session.pop("a") == 2
        del session["b"]
        assert session.setdefault("c", 9) == 4
        session.clear()
        assert dict(session) == {"_permanent": False}

    def test_business_field_still_free(self):
        session = make_session({"cart": {"items": []}})
        session["cart"]["items"].append("x")
        session["cart"]["new"] = 1
        assert exact_type(session["cart"], dict)
        assert session["cart"] == {"items": ["x"], "new": 1}


class TestDirectWrites:
    def test_setitem_denied_preserves_state(self):
        session = make_session({"user_id": 7})
        before = dict(session)
        with pytest.raises(ProtectedFieldError):
            session["user_id"] = 8
        assert dict(session) == before
        assert session["user_id"] == 7

    def test_delitem_denied_preserves_state(self):
        session = make_session({"user_id": 7})
        with pytest.raises(ProtectedFieldError):
            del session["user_id"]
        assert session["user_id"] == 7

    def test_granted_scope_allows_write_then_revokes(self):
        session = make_session({"user_id": 7, "auth_level": 1})
        with session.grant_scopes("auth", "mfa"):
            session["user_id"] = 99
            del session["auth_level"]
        assert session["user_id"] == 99
        assert "auth_level" not in session
        with pytest.raises(ProtectedFieldError):
            session["user_id"] = 1

    def test_any_listed_scope_authorizes(self):
        session = make_session({"auth_level": 1})
        with session.grant_scopes("mfa"):
            session["auth_level"] = 2
        assert session["auth_level"] == 2

    def test_wrong_scope_still_denied(self):
        session = make_session({"user_id": 7})
        with session.grant_scopes("billing"), pytest.raises(ProtectedFieldError):
            session["user_id"] = 8
        assert session["user_id"] == 7

    def test_nested_grants_restore_outer_scope(self):
        session = make_session({"user_id": 7, "auth_level": 1})
        with session.grant_scopes("auth"):
            with session.grant_scopes("billing"):  # noqa: SIM117
                pass
            # outer scope still active after inner block exits
            session["user_id"] = 42
        # all scopes gone outside the outer block
        with pytest.raises(ProtectedFieldError):
            session["auth_level"] = 3


class TestUpdatePopClear:
    def test_update_mixed_is_all_or_nothing(self):
        session = make_session({"user_id": 7})
        before = dict(session)
        with pytest.raises(ProtectedFieldError):
            session.update({"user_id": 8, "cart": {"a": 1}})
        assert dict(session) == before
        assert "cart" not in session

    def test_update_with_scope(self):
        session = make_session({"user_id": 7})
        with session.grant_scopes("auth"):
            session.update(user_id=8, profile={"name": "a"})
        assert session["user_id"] == 8
        assert session["profile"] == {"name": "a"}

    def test_pop_denied_keeps_value(self):
        session = make_session({"user_id": 7})
        with pytest.raises(ProtectedFieldError):
            session.pop("user_id")
        assert session["user_id"] == 7

    def test_pop_with_default_still_denied(self):
        session = make_session({"user_id": 7})
        with pytest.raises(ProtectedFieldError):
            session.pop("user_id", None)
        assert session["user_id"] == 7

    def test_setdefault_denied_for_missing_protected_key(self):
        session = make_session({})
        with pytest.raises(ProtectedFieldError):
            session.setdefault("profile", {})
        assert "profile" not in session

    def test_popitem_blocked_when_protected_present(self):
        session = make_session({"user_id": 7, "cart": 1})
        with pytest.raises(ProtectedFieldError):
            session.popitem()
        assert dict(session) == {"user_id": 7, "cart": 1}

    def test_clear_denied_keeps_entire_state(self):
        session = make_session({"user_id": 7})
        session["cart"] = 1
        before = dict(session)
        with pytest.raises(ProtectedFieldError):
            session.clear()
        assert dict(session) == before

    def test_clear_with_scope_keeps_permanent(self):
        session = make_session({"user_id": 7, "cart": 1})
        session["_permanent"] = True
        with session.grant_scopes("auth", "mfa"):
            session.clear()
        assert dict(session) == {"_permanent": True}


class TestNestedMutation:
    def test_nested_dict_guarded(self):
        session = make_session({"profile": {"address": {"city": "x"}}})
        assert isinstance(session["profile"], ProtectedDict)
        with pytest.raises(ProtectedFieldError):
            session["profile"]["address"]["city"] = "y"
        with pytest.raises(ProtectedFieldError):
            session["profile"]["new"] = 1
        with pytest.raises(ProtectedFieldError):
            del session["profile"]["address"]
        with session.grant_scopes("auth"):
            session["profile"]["address"]["city"] = "y"
        assert session["profile"]["address"]["city"] == "y"

    def test_nested_list_guarded(self):
        session = make_session({"profile": {"tags": ["a"]}})
        tags = session["profile"]["tags"]
        assert isinstance(tags, ProtectedList)
        for mutation in (
            lambda: tags.append("b"),
            lambda: tags.extend(["b"]),
            lambda: tags.insert(0, "b"),
            lambda: tags.remove("a"),
            lambda: tags.pop(),
            lambda: tags.clear(),
            lambda: tags.sort(),
            lambda: tags.reverse(),
        ):
            with pytest.raises(ProtectedFieldError):  # noqa: SIM117
                mutation()
        assert tags == ["a"]
        with session.grant_scopes("auth"):
            tags.append("b")
        assert tags == ["a", "b"]

    def test_nested_set_guarded(self):
        session = make_session({"profile": {"roles": {"admin"}}})
        roles = session["profile"]["roles"]
        assert isinstance(roles, ProtectedSet)
        with pytest.raises(ProtectedFieldError):
            roles.add("user")
        with pytest.raises(ProtectedFieldError):
            roles.discard("admin")
        assert roles == {"admin"}
        with session.grant_scopes("auth"):
            roles.add("user")
        assert roles == {"admin", "user"}

    def test_nested_dict_methods_denied(self):
        session = make_session({"profile": {"a": 1}})
        inner = session["profile"]
        with pytest.raises(ProtectedFieldError):
            inner.update({"b": 2})
        assert "b" not in inner
        with pytest.raises(ProtectedFieldError):
            inner.pop("a")
        with pytest.raises(ProtectedFieldError):
            inner.setdefault("b", 2)
        with pytest.raises(ProtectedFieldError):
            inner.clear()
        assert inner == {"a": 1}

    def test_nested_value_assignment_rewrapped(self):
        session = make_session({"profile": {}})
        with session.grant_scopes("auth"):
            session["profile"]["nested"] = {"k": [1]}
        nested = session["profile"]["nested"]
        assert isinstance(nested, ProtectedDict)
        assert isinstance(nested["k"], ProtectedList)
        with pytest.raises(ProtectedFieldError):
            nested["k"].append(2)


class TestSerializationAndRestore:
    def test_guards_serialize_as_plain_builtins(self):
        import pickle

        session = make_session(
            {"profile": {"n": {"k": 1}, "lst": [1], "s": {1}}}
        )
        plain = pickle.loads(pickle.dumps(dict(session)))
        assert exact_type(plain["profile"], dict)
        assert exact_type(plain["profile"]["n"], dict)
        assert exact_type(plain["profile"]["lst"], list)
        assert exact_type(plain["profile"]["s"], set)

    def test_restored_session_reapplies_guards(self):
        session = make_session({"profile": {"tags": ["a"]}})
        stored = dict(session)
        restored = ServerSideSession(
            initial=stored, sid="sid2", protected_fields=PROTECTED
        )
        with pytest.raises(ProtectedFieldError):
            restored["profile"]["tags"].append("b")
        with restored.grant_scopes("auth"):
            restored["profile"]["tags"].append("b")
        assert restored["profile"]["tags"] == ["a", "b"]

    def test_policy_is_not_serialized_into_data(self):
        session = make_session({"user_id": 7})
        assert "protected_fields" not in dict(session)
        assert "_active_scopes" not in dict(session)


class TestScopeIsolation:
    def test_scopes_not_shared_between_instances(self):
        first = make_session({"user_id": 1})
        second = make_session({"user_id": 2})
        with first.grant_scopes("auth"), pytest.raises(ProtectedFieldError):
            first["user_id"] = 10
            second["user_id"] = 20
        assert first["user_id"] == 10
        assert second["user_id"] == 2

    def test_scope_released_on_exception(self):
        session = make_session({"user_id": 7})
        with pytest.raises(RuntimeError), session.grant_scopes("auth"):
            raise RuntimeError("boom")
        with pytest.raises(ProtectedFieldError):
            session["user_id"] = 8


class TestWholeDictReplacement:
    def test_update_cannot_bypass_with_full_mapping(self):
        session = make_session({"user_id": 7})
        attacker = {"user_id": 999, "auth_level": 0, "cart": "x"}
        with pytest.raises(ProtectedFieldError):
            session.update(attacker)
        assert session["user_id"] == 7
        assert "auth_level" not in session or session.get("auth_level") is None
        assert "cart" not in session

    def test_setitem_on_each_protected_key_guarded(self):
        session = make_session({})
        for key in ("user_id", "auth_level", "profile"):
            with pytest.raises(ProtectedFieldError):
                session[key] = "attacker"
        assert dict(session) == {}


class TestEndToEndCachelib:
    session_dir = "testing_protected_storage"

    def _app(self):
        app = flask.Flask(__name__)
        app.config.update(
            {
                "SECRET_KEY": "secret",
                "SESSION_TYPE": "cachelib",
                "SESSION_SERIALIZATION_FORMAT": "json",
                "SESSION_PERMANENT": False,
                "SESSION_CACHELIB": FileSystemCache(
                    threshold=500, cache_dir=self.session_dir
                ),
                "SESSION_PROTECTED_FIELDS": PROTECTED,
            }
        )
        Session(app)
        return app

    def teardown_method(self):
        if os.path.isdir(self.session_dir):
            shutil.rmtree(self.session_dir)

    def test_request_cycle_enforcement_and_restore(self):
        app = self._app()

        @app.route("/login", methods=["POST"])
        def login():
            with flask.session.grant_scopes("auth"):
                flask.session["user_id"] = flask.request.form["uid"]
                flask.session["profile"] = {"tags": ["a"]}
            flask.session["cart"] = []
            return "ok"

        @app.route("/attack", methods=["POST"])
        def attack():
            try:
                flask.session["user_id"] = "attacker"
            except ProtectedFieldError:
                return "blocked", 403
            return "ok"

        @app.route("/nested-attack", methods=["POST"])
        def nested_attack():
            try:
                flask.session["profile"]["tags"].append("b")
            except ProtectedFieldError:
                return "blocked", 403
            return "ok"

        @app.route("/whoami")
        def whoami():
            return flask.session.get("user_id", "anon")

        client = app.test_client()
        assert client.post("/login", data={"uid": "42"}).status_code == 200
        assert client.post("/attack").status_code == 403
        assert client.post("/nested-attack").status_code == 403
        assert client.get("/whoami").data == b"42"

        # Stored data uses plain builtins and no policy metadata leaked.
        cookie = client.get_cookie(app.config["SESSION_COOKIE_NAME"])
        assert cookie is not None
        stored = app.session_interface.cache.get(
            f"session:{cookie.value}"
        )
        assert exact_type(stored["profile"], dict)
        assert exact_type(stored["profile"]["tags"], list)
        assert "protected_fields" not in stored
        assert "_active_scopes" not in stored

    def test_scope_does_not_leak_across_requests(self):
        app = self._app()

        @app.route("/grant")
        def grant():
            with flask.session.grant_scopes("auth"):
                flask.session["user_id"] = 1
            return "ok"

        @app.route("/try")
        def try_write():
            try:
                flask.session["user_id"] = 2
            except ProtectedFieldError:
                return "blocked", 403
            return "ok"

        client = app.test_client()
        assert client.get("/grant").status_code == 200
        assert client.get("/try").status_code == 403
