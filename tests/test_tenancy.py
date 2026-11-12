import os
import shutil
from contextlib import contextmanager

import flask
import pytest
from cachelib.file import FileSystemCache
from flask_session.cachelib import CacheLibSessionInterface
from flask_session.tenancy import (
    TenantFieldError,
    TenantPolicy,
    TenantSessionInterfaceMixin,
    establish_tenant,
    policy_from_config,
    switch_tenant,
)


class TenantCacheLibSessionInterface(
    TenantSessionInterfaceMixin, CacheLibSessionInterface
):
    pass


# Field-ownership configuration example: global preferences survive a tenant
# switch, tenant capabilities are revoked, and anything not listed here is
# treated as tenant-scoped (never migrates across tenants by default).
TENANT_CONFIG = {
    "SESSION_TENANT_FIELD_OWNERSHIP": {
        "locale": "global",
        "theme": "global",
        "roles": "tenant",
        "permissions": "tenant",
    },
    "SESSION_TENANT_UNKNOWN_FIELD": "tenant",
}


class TestTenancy:
    session_dir = "testing_tenancy_session_storage"

    @contextmanager
    def setup_storage(self):
        try:
            yield
        finally:
            if os.path.isdir(self.session_dir):
                shutil.rmtree(self.session_dir)

    def create_app(self, extra_config=None):
        app = flask.Flask(__name__)
        app.config.update(TENANT_CONFIG)
        app.config["SESSION_PERMANENT"] = False
        if extra_config:
            app.config.update(extra_config)
        app.session_interface = TenantCacheLibSessionInterface(
            app=app,
            client=FileSystemCache(threshold=500, cache_dir=self.session_dir),
            serialization_format="json",
        )

        @app.route("/login/<tenant>", methods=["POST"])
        def login(tenant):
            establish_tenant(flask.session, tenant)
            flask.session["locale"] = "en"  # global preference
            flask.session["roles"] = ["admin"]  # tenant capability
            flask.session["cart"] = ["item-1"]  # unknown field
            return "ok"

        @app.route("/switch/<tenant>", methods=["POST"])
        def switch(tenant):
            switch_tenant(
                flask.session,
                tenant,
                policy=policy_from_config(app.config),
                app=flask.current_app._get_current_object(),
            )
            return "ok"

        @app.route("/set", methods=["POST"])
        def set_value():
            flask.session["value"] = flask.request.form["value"]
            return "value set"

        @app.route("/state")
        def state():
            return dict(flask.session)

        return app

    def test_state_layering_and_switch(self):
        with self.setup_storage():
            app = self.create_app()
            client = app.test_client()
            interface = app.session_interface

            client.post("/login/tenant-a")
            old_sid = client.get_cookie("session").value

            state = client.get("/state").get_json()
            assert state["_tenant_id"] == "tenant-a"
            assert state["_tenant_epoch"] == 1

            client.post("/switch/tenant-b")
            new_sid = client.get_cookie("session").value

            # Old tenant capabilities are revoked server-side, new id issued
            assert new_sid != old_sid
            assert interface.cache.get(f"session:{old_sid}") is None

            state = client.get("/state").get_json()
            # Global preferences are kept
            assert state["locale"] == "en"
            # Tenant-scoped capabilities are revoked
            assert "roles" not in state
            # Unknown fields do not migrate across tenants by default
            assert "cart" not in state
            # Exactly one consistent tenant state is visible
            assert state["_tenant_id"] == "tenant-b"
            assert state["_tenant_epoch"] == 2

    def test_failed_switch_leaves_no_splice(self, monkeypatch):
        with self.setup_storage():
            app = self.create_app()
            client = app.test_client()
            interface = app.session_interface

            client.post("/login/tenant-a")
            old_sid = client.get_cookie("session").value
            before = client.get("/state").get_json()

            def failing_delete(store_id):
                raise RuntimeError("storage unavailable")

            monkeypatch.setattr(interface, "_delete_session", failing_delete)
            response = client.post("/switch/tenant-b")
            assert response.status_code == 500

            # In-memory and stored state are exactly the pre-switch state
            state = client.get("/state").get_json()
            assert state == before
            stored = interface.cache.get(f"session:{old_sid}")
            assert stored["roles"] == ["admin"]
            assert stored["_tenant_id"] == "tenant-a"

    def test_failed_switch_restores_stored_session(self, monkeypatch):
        with self.setup_storage():
            app = self.create_app()
            client = app.test_client()
            interface = app.session_interface

            client.post("/login/tenant-a")
            old_sid = client.get_cookie("session").value
            old_store_id = f"session:{old_sid}"
            original_upsert = CacheLibSessionInterface._upsert_session

            def failing_upsert(self, lifetime, session, store_id):
                if store_id != old_store_id:
                    raise RuntimeError("write failed mid-switch")
                return original_upsert(self, lifetime, session, store_id)

            monkeypatch.setattr(
                CacheLibSessionInterface, "_upsert_session", failing_upsert
            )
            response = client.post("/switch/tenant-b")
            assert response.status_code == 500

            # The old stored session was restored; no half-written new tenant
            stored = interface.cache.get(old_store_id)
            assert stored["_tenant_id"] == "tenant-a"
            assert stored["roles"] == ["admin"]
            session_files = [
                name
                for name in os.listdir(self.session_dir)
                if not interface.cache._is_mgmt(name)
            ]
            assert session_files == [
                os.path.basename(interface.cache._get_filename(old_store_id))
            ]

            state = client.get("/state").get_json()
            assert state["_tenant_id"] == "tenant-a"
            assert state["roles"] == ["admin"]

    def test_interleaved_requests_see_one_consistent_tenant(self):
        with self.setup_storage():
            app = self.create_app()
            client = app.test_client()
            interface = app.session_interface

            client.post("/login/tenant-a")
            old_sid = client.get_cookie("session").value

            # Request 1 (normal save) opens its session before the switch.
            ctx = app.test_request_context(
                "/set",
                method="POST",
                data={"value": "stale"},
                headers={"Cookie": f"session={old_sid}"},
            )
            ctx.push()
            flask.session["value"] = "stale"
            stale_session = flask.session._get_current_object()

            # Request 2 (tenant switch) runs to completion in the meantime.
            assert client.post("/switch/tenant-b").status_code == 200
            new_sid = client.get_cookie("session").value

            # Request 1 only now tries to save its old-tenant state.
            stale_response = app.response_class()
            interface.save_session(app, stale_session, stale_response)
            ctx.pop()

            # The stale save was dropped: no storage write, no cookie issued.
            assert stale_response.headers.getlist("Set-Cookie") == []
            assert interface.cache.get(f"session:{old_sid}") is None
            stored_new = interface.cache.get(f"session:{new_sid}")
            assert "value" not in stored_new

            # Request 3 observes exactly one consistent tenant state.
            state = client.get("/state").get_json()
            assert state["_tenant_id"] == "tenant-b"
            assert state["_tenant_epoch"] == 2
            assert state["locale"] == "en"
            assert "roles" not in state
            assert "value" not in state

            # Normal saves after the switch still work.
            assert client.post("/set", data={"value": "fresh"}).status_code == 200
            assert client.get("/state").get_json()["value"] == "fresh"

    def test_unknown_field_error_policy_rejects_switch(self):
        with self.setup_storage():
            app = self.create_app({"SESSION_TENANT_UNKNOWN_FIELD": "error"})
            interface = app.session_interface
            policy = policy_from_config(app.config)

            session = interface.session_class(
                {
                    "_tenant_id": "tenant-a",
                    "_tenant_epoch": 1,
                    "locale": "en",
                    "mystery": "data",
                },
                sid="sid-a",
            )
            with pytest.raises(TenantFieldError):
                switch_tenant(session, "tenant-b", policy=policy)

            # Nothing was spliced: the session is untouched
            assert dict(session) == {
                "_tenant_id": "tenant-a",
                "_tenant_epoch": 1,
                "locale": "en",
                "mystery": "data",
            }
            assert session.sid == "sid-a"

    def test_policy_validation(self):
        with pytest.raises(ValueError, match="ownership layer"):
            TenantPolicy({"roles": "sometimes"})
        with pytest.raises(ValueError, match="reserved"):
            TenantPolicy({"_tenant_id": "global"})
        with pytest.raises(ValueError, match="unknown_field"):
            TenantPolicy(unknown_field="global")
        with pytest.raises(ValueError, match="non-empty"):
            switch_tenant(
                TenantCacheLibSessionInterface.session_class(), "", TenantPolicy()
            )
