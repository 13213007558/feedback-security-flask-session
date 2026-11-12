Multi-tenant sessions
------------------------------------

When one user can switch between tenants, the session carries two layers of
state and every field must have an explicit owner:

- **global**: user-level preferences (e.g. ``locale``, ``theme``) that survive
  a tenant switch.
- **tenant**: capabilities of the *current* tenant (e.g. ``roles``,
  ``permissions``) that are revoked the moment the tenant changes.

Field ownership is declared per field; anything not listed never migrates
across tenants by default:

.. code-block:: python

    SESSION_TENANT_FIELD_OWNERSHIP = {
        "locale": "global",
        "theme": "global",
        "roles": "tenant",
        "permissions": "tenant",
    }
    # Unknown fields are tenant-scoped (default-deny) so they cannot follow
    # permissions across a switch. Use "error" to reject switches that carry
    # undeclared fields instead.
    SESSION_TENANT_UNKNOWN_FIELD = "tenant"

Switch tenant atomically and guard against stale in-flight requests:

.. code-block:: python

    import flask
    from flask_session.tenancy import (
        TenantSessionInterfaceMixin,
        establish_tenant,
        policy_from_config,
        switch_tenant,
    )
    from flask_session.cachelib import CacheLibSessionInterface

    class TenantCacheLibSessionInterface(
        TenantSessionInterfaceMixin, CacheLibSessionInterface
    ):
        pass

    app.session_interface = TenantCacheLibSessionInterface(
        app=app, client=FileSystemCache("flask_session"), serialization_format="json"
    )

    @app.post("/switch/<tenant>")
    def switch(tenant):
        switch_tenant(
            flask.session,
            tenant,
            policy=policy_from_config(flask.current_app.config),
            app=flask.current_app._get_current_object(),
        )
        return "ok"

Guarantees:

- ``switch_tenant`` keeps approved shared (global) data, revokes the old
  tenant's server-side state, issues a fresh session id, and bumps a tenant
  epoch counter.
- Any failure raises ``TenantSwitchError``/``TenantFieldError`` and leaves the
  session in its exact pre-switch state -- never a splice of both tenants'
  permissions. If the storage update fails midway, the old stored session is
  restored on a best-effort basis.
- ``TenantSessionInterfaceMixin`` drops saves from requests that opened their
  session before a switch completed, so interleaved requests can never
  resurrect old-tenant capabilities; subsequent requests observe exactly one
  consistent tenant state.
