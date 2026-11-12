Protected session fields
========================

In an application composed of multiple extensions, every extension can write to
the shared :data:`flask.session` mapping. Some fields, such as the authenticated
identity (``user_id``) or the authentication strength (``auth_level``), should
only be changeable by the authentication extension. Flask-Session provides an
opt-in **protected fields** mechanism for this. Ordinary, unlisted fields keep
their normal dictionary behavior, so existing code is unaffected until you
explicitly configure protection.

Configuration
-------------

Map each protected field to the scope (or an iterable of scopes) that is
allowed to write it. A write succeeds when *any one* of the field's scopes is
currently active::

    app.config["SESSION_PROTECTED_FIELDS"] = {
        "user_id": "auth",
        "auth_level": ["auth", "mfa"],
    }

The default is an empty mapping, which disables the feature entirely and leaves
the session behaving exactly like a plain dictionary.

Granting scopes
---------------

Scopes are granted per request and only for the duration of a ``with`` block by
using :meth:`~flask_session.base.ServerSideSession.grant_scopes`. The
authentication extension wraps its identity-changing writes in such a block::

    from flask import session

    with session.grant_scopes("auth"):
        session["user_id"] = current_user.id
        session["auth_level"] = "mfa"

When the block exits, the previous scopes are restored. Scopes live on the
request-scoped session object: a new session instance is created for every
request, so a scope granted in one request or one thread can never be reused by
another, including concurrent requests.

What is enforced
----------------

All dictionary mutation paths check the active scopes before changing anything:

- item assignment and deletion (``session[k] = v``, ``del session[k]``)
- :meth:`~dict.update`, :meth:`~dict.pop`, :meth:`~dict.popitem`,
  :meth:`~dict.setdefault` and :meth:`~flask_session.base.ServerSideSession.clear`
- in-place mutation of nested ``dict``, ``list`` and ``set`` values stored under
  a protected field, at any depth

Refusals raise :class:`~flask_session.exceptions.ProtectedFieldError` (a
subclass of :class:`PermissionError`) *before* any state changes. Batch
operations such as ``update`` validate every targeted field up front, so a
single unauthorized field leaves the whole session in its previous, consistent
state. Replacing the mapping wholesale with ``session.update({...})`` is covered
by the same checks and cannot be used to bypass protection.

Storage and restoration
-----------------------

The protection policy and the active scopes are never stored with the session
data. Nested containers are serialized as plain built-in types; when a session
is loaded from storage the guards are re-applied from the application
configuration, so a restored session enforces the same rules without trusting
any data read back from storage.
