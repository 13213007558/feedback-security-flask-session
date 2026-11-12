"""Multi-tenant state layering and atomic tenant switching for server-side sessions.

A session belonging to a user who can switch tenants carries two layers of
state:

- **global** fields: user-level preferences (e.g. ``locale``, ``theme``) that
  survive a tenant switch.
- **tenant** fields: capabilities of the *current* tenant (e.g. ``roles``,
  ``permissions``) that are revoked the moment the tenant changes.

Field ownership is declared explicitly through configuration, for example::

    SESSION_TENANT_FIELD_OWNERSHIP = {
        "locale": "global",
        "theme": "global",
        "roles": "tenant",
        "permissions": "tenant",
    }
    SESSION_TENANT_UNKNOWN_FIELD = "tenant"  # or "error"

Fields without a configured owner are *never* silently carried across a
tenant switch: by default they are treated as tenant-scoped and are revoked
on switch (default-deny). Set ``SESSION_TENANT_UNKNOWN_FIELD = "error"`` to
reject switches while unknown fields are present instead.

Use :func:`establish_tenant` after login, :func:`switch_tenant` to change
tenant, and mix :class:`TenantSessionInterfaceMixin` into the session
interface so that a slow request that opened its session *before* a switch
cannot resurrect or splice old-tenant capabilities when it saves afterwards.
"""

from contextlib import suppress
from datetime import timedelta as TimeDelta
from typing import Any, Dict, Optional

from flask import Flask

from .base import ServerSideSession, ServerSideSessionInterface
from .defaults import Defaults

#: Ownership layer for fields that survive a tenant switch.
LAYER_GLOBAL = "global"
#: Ownership layer for fields that are revoked on a tenant switch.
LAYER_TENANT = "tenant"

_LAYERS = (LAYER_GLOBAL, LAYER_TENANT)
_UNKNOWN_POLICIES = (LAYER_TENANT, "error")


class TenantFieldError(ValueError):
    """A session field has no configured ownership and the policy forbids
    implicitly layering unknown fields."""


class TenantSwitchError(RuntimeError):
    """A tenant switch failed. The live session is left in its exact
    pre-switch state; it never contains a splice of both tenants."""


class TenantPolicy:
    """Declares which session fields are global and which are tenant-scoped.

    :param field_ownership: Mapping of session field name to ``"global"`` or
        ``"tenant"``.
    :param unknown_field: How to treat fields with no configured owner.
        ``"tenant"`` (default) revokes them on switch so unknown fields never
        migrate across tenants; ``"error"`` raises :class:`TenantFieldError`
        instead.

    .. attribute:: TENANT_KEY

    Session key holding the current tenant id (``"_tenant_id"``).

    .. attribute:: EPOCH_KEY

    Session key holding the tenant generation counter (``"_tenant_epoch"``).
    It is incremented on every switch so that stale in-flight requests can be
    detected.
    """

    TENANT_KEY = "_tenant_id"
    EPOCH_KEY = "_tenant_epoch"

    #: Keys managed by the framework; always survive a switch.
    _RESERVED_KEYS = (TENANT_KEY, EPOCH_KEY, "_permanent")

    def __init__(
        self,
        field_ownership: Optional[Dict[str, str]] = None,
        unknown_field: str = LAYER_TENANT,
    ):
        self.field_ownership = dict(field_ownership or {})
        invalid = {
            key: layer
            for key, layer in self.field_ownership.items()
            if layer not in _LAYERS
        }
        if invalid:
            raise ValueError(
                f"Invalid ownership layer(s) {invalid!r}; expected one of {_LAYERS}."
            )
        reserved = self.field_ownership.keys() & self._RESERVED_KEYS
        if reserved:
            raise ValueError(
                f"Field(s) {sorted(reserved)} are reserved and cannot be assigned a layer."
            )
        if unknown_field not in _UNKNOWN_POLICIES:
            raise ValueError(
                f"unknown_field must be one of {_UNKNOWN_POLICIES}, got {unknown_field!r}."
            )
        self.unknown_field = unknown_field

    def ownership_of(self, field: str) -> str:
        """Return the ownership layer for a session field."""
        if field in self._RESERVED_KEYS:
            return LAYER_GLOBAL
        if field in self.field_ownership:
            return self.field_ownership[field]
        if self.unknown_field == "error":
            raise TenantFieldError(
                f"Session field {field!r} has no configured ownership; "
                "refusing to let it follow permissions across tenants."
            )
        # Default-deny: unknown fields are tenant-scoped, so they are revoked
        # on switch instead of migrating across tenants with the permissions.
        return LAYER_TENANT

    def build_switch_state(
        self, current: Dict[str, Any], new_tenant_id: str
    ) -> Dict[str, Any]:
        """Compute the post-switch session state without touching the session.

        Keeps approved shared (global) data, drops every tenant-scoped field,
        and bumps the tenant epoch.
        """
        next_state = {
            key: value
            for key, value in current.items()
            if self.ownership_of(key) == LAYER_GLOBAL
        }
        next_state[self.TENANT_KEY] = new_tenant_id
        next_state[self.EPOCH_KEY] = int(current.get(self.EPOCH_KEY, 0)) + 1
        return next_state


def policy_from_config(config: Optional[Dict[str, Any]] = None) -> TenantPolicy:
    """Build a :class:`TenantPolicy` from an app config (or mapping)."""
    config = config or {}
    return TenantPolicy(
        field_ownership=config.get(
            "SESSION_TENANT_FIELD_OWNERSHIP", Defaults.SESSION_TENANT_FIELD_OWNERSHIP
        ),
        unknown_field=config.get(
            "SESSION_TENANT_UNKNOWN_FIELD", Defaults.SESSION_TENANT_UNKNOWN_FIELD
        ),
    )


def establish_tenant(
    session: ServerSideSession, tenant_id: str, policy: Optional[TenantPolicy] = None
) -> ServerSideSession:
    """Attach a fresh session to its first tenant, e.g. right after login."""
    if not tenant_id or not isinstance(tenant_id, str):
        raise ValueError("tenant_id must be a non-empty string")
    session[TenantPolicy.TENANT_KEY] = tenant_id
    session[TenantPolicy.EPOCH_KEY] = 1
    return session


def switch_tenant(
    session: ServerSideSession,
    new_tenant_id: str,
    policy: Optional[TenantPolicy] = None,
    app: Optional[Flask] = None,
    interface: Optional[ServerSideSessionInterface] = None,
) -> ServerSideSession:
    """Atomically move *session* to *new_tenant_id*.

    The switch:

    1. computes the next state on a copy (global fields kept, tenant-scoped
       capabilities dropped, epoch bumped) without touching the live session;
    2. revokes the old tenant's capabilities server-side by deleting the old
       stored session, issuing a new session id and storing the new state
       under it;
    3. commits the new state to the live session in one step.

    Any failure raises :class:`TenantSwitchError` (or
    :class:`TenantFieldError`) and leaves the session in its exact pre-switch
    state -- never a splice of both tenants' permissions. If the server-side
    update fails midway, the old stored session is restored on a best-effort
    basis.
    """
    policy = policy or TenantPolicy()
    if not new_tenant_id or not isinstance(new_tenant_id, str):
        raise ValueError("new_tenant_id must be a non-empty string")
    if interface is None and app is not None:
        interface = app.session_interface

    current = dict(session)
    current_sid = session.sid

    # Phase 1: pure computation, may raise TenantFieldError before anything
    # is mutated.
    next_state = policy.build_switch_state(current, new_tenant_id)

    # Phase 2: revoke old-tenant capabilities in storage and persist the new
    # state under a fresh session id.
    new_sid = current_sid
    if interface is not None:
        lifetime = (
            app.permanent_session_lifetime
            if app is not None
            else TimeDelta(days=31)
        )
        old_store_id = interface._get_store_id(current_sid)
        new_sid = interface._generate_sid(interface.sid_length)
        new_store_id = interface._get_store_id(new_sid)
        try:
            interface._delete_session(old_store_id)
            interface._upsert_session(
                lifetime,
                interface.session_class(next_state, sid=new_sid),
                new_store_id,
            )
        except Exception as exc:
            # Best-effort rollback so the old tenant is not left half-revoked.
            with suppress(Exception):
                interface._upsert_session(
                    lifetime,
                    interface.session_class(current, sid=current_sid),
                    old_store_id,
                )
            raise TenantSwitchError(
                f"Failed to switch tenant to {new_tenant_id!r}; "
                "the session was left unchanged."
            ) from exc

    # Phase 3: commit to the live session atomically, rolling back the
    # in-memory state if anything fails.
    try:
        session.clear()
        session.update(next_state)
        session.sid = new_sid
        session.modified = True
    except Exception as exc:
        session.clear()
        session.update(current)
        session.sid = current_sid
        session.modified = True
        raise TenantSwitchError(
            f"Failed to switch tenant to {new_tenant_id!r}; "
            "the session was rolled back."
        ) from exc
    return session


class TenantSessionInterfaceMixin:
    """Mixin for session interfaces that rejects stale cross-tenant saves.

    When a request opened its session before a tenant switch completed, its
    later save would otherwise resurrect old-tenant capabilities or splice
    them into the new tenant's state. This mixin drops such saves: a session
    whose stored epoch is newer than the in-memory one (or whose stored state
    was deleted by the switch) is not written back, and no cookie is issued.
    """

    def open_session(self, app: Flask, request) -> ServerSideSession:
        session = super().open_session(app, request)
        if session.get(TenantPolicy.EPOCH_KEY) is None:
            # No tenant state was loaded from storage, so a tenant established
            # later in this request (e.g. at login) is not a stale save.
            session._tenant_fresh = True
        return session

    def _is_stale_tenant_save(self, session: ServerSideSession) -> bool:
        epoch = session.get(TenantPolicy.EPOCH_KEY)
        if epoch is None:
            return False  # not a tenant-bound session
        if getattr(session, "_tenant_fresh", False):
            return False  # tenant state was created by this very request
        stored = self._retrieve_session_data(self._get_store_id(session.sid))
        if stored is None:
            return True  # deleted by a completed switch (or logout)
        stored_epoch = stored.get(TenantPolicy.EPOCH_KEY)
        return stored_epoch is not None and stored_epoch > epoch

    def save_session(
        self, app: Flask, session: ServerSideSession, response
    ) -> None:
        if self._is_stale_tenant_save(session):
            # A tenant switch completed after this request opened its session.
            # Discard the save so subsequent requests only ever observe one
            # consistent tenant state.
            return
        return super().save_session(app, session, response)
