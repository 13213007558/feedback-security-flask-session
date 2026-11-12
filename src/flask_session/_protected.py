"""Guarded containers for protected session fields.

Protected fields may hold nested mutable values (dicts, lists, sets). The
:class:`~flask_session.base.ServerSideSession` itself only intercepts direct
key writes, so a plain nested ``dict`` could otherwise be mutated in place
without ever touching the session mapping.

The wrappers in this module wrap every nested mutable value and forward the
configured scope check to every mutating operation. Read-only operations are
transparent. Wrappers are only applied to values of protected fields; values of
ordinary fields keep behaving exactly like a normal dictionary.

The wrappers are *not* serialized themselves: each backend serializes the
unwrapped data (``dict(session)``), so storage only ever sees plain built-in
types.
"""

from __future__ import annotations

from typing import Any, Callable

# A checker receives the targeted field key and raises
# :class:`~flask_session.exceptions.ProtectedFieldError` when the active
# scopes do not authorize the write.
ScopeChecker = Callable[[str], None]


def wrap_value(value: Any, key: str, check: ScopeChecker) -> Any:
    """Wrap nested mutable containers of a protected field.

    Immutable values are returned untouched so identity and equality semantics
    for ordinary scalar values are preserved.
    """
    if isinstance(value, ProtectedContainer):
        # Re-bind with the current checker/key in case the object was carried
        # over from another session (e.g. a session restored from storage) and
        # recursively re-bind descendants so no guard keeps a stale owner.
        value._bind(key, check)
        value._rebind_children(key, check)
        return value
    if isinstance(value, dict):
        return ProtectedDict(value, key, check)
    if isinstance(value, list):
        return ProtectedList(value, key, check)
    if isinstance(value, set):
        return ProtectedSet(value, key, check)
    return value


def unwrap_value(value: Any) -> Any:
    """Return a plain built-in copy with every guard removed.

    Used when a guarded value reaches serialization so storage only ever sees
    plain ``dict``/``list``/``set`` objects. On the next request the session
    constructor re-applies the guards based on the protected field policy.
    """
    if isinstance(value, ProtectedDict):
        return {inner_key: unwrap_value(inner) for inner_key, inner in value.items()}
    if isinstance(value, ProtectedList):
        return [unwrap_value(inner) for inner in value]
    if isinstance(value, ProtectedSet):
        return {unwrap_value(inner) for inner in value}
    if isinstance(value, dict):
        return {
            inner_key: unwrap_value(inner) for inner_key, inner in value.items()
        }
    if isinstance(value, list):
        return [unwrap_value(inner) for inner in value]
    if isinstance(value, set):
        return {unwrap_value(inner) for inner in value}
    return value


class ProtectedContainer:
    """Shared binding logic for guarded nested containers."""

    def _bind(self, key: str, check: ScopeChecker) -> None:
        self._protected_key = key
        self._check = check

    def _authorize(self) -> None:
        self._check(self._protected_key)

    def _rebind_children(self, key: str, check: ScopeChecker) -> None:
        """Re-point every nested guard at the same owner and field."""
        for child in self._guarded_children():
            wrap_value(child, key, check)

    def _guarded_children(self):
        return ()


class ProtectedDict(ProtectedContainer, dict):
    """A ``dict`` nested under a protected field that enforces scope on writes."""

    def __init__(
        self, data: dict, key: str, check: ScopeChecker
    ) -> None:
        super().__init__(
            {
                inner_key: wrap_value(inner_value, key, check)
                for inner_key, inner_value in data.items()
            }
        )
        self._bind(key, check)

    def _guarded_children(self):
        return self.values()

    def __setitem__(self, inner_key: Any, value: Any) -> None:
        self._authorize()
        super().__setitem__(
            inner_key, wrap_value(value, self._protected_key, self._check)
        )

    def __delitem__(self, inner_key: Any) -> None:
        self._authorize()
        super().__delitem__(inner_key)

    def clear(self) -> None:
        self._authorize()
        super().clear()

    def update(self, *args: Any, **kwargs: Any) -> None:
        self._authorize()
        merged: dict = {}
        if args:
            if len(args) > 1:
                raise TypeError(
                    f"update expected at most 1 argument, got {len(args)}"
                )
            other = args[0]
            if hasattr(other, "keys"):
                for inner_key in other:
                    merged[inner_key] = other[inner_key]
            else:
                merged.update(other)
        merged.update(kwargs)
        for inner_key, value in merged.items():
            super().__setitem__(
                inner_key,
                wrap_value(value, self._protected_key, self._check),
            )

    def setdefault(self, inner_key: Any, default: Any = None) -> Any:
        if inner_key not in self:
            self._authorize()
            super().__setitem__(
                inner_key,
                wrap_value(default, self._protected_key, self._check),
            )
        return super().__getitem__(inner_key)

    def pop(self, inner_key: Any, *default: Any) -> Any:
        self._authorize()
        return super().pop(inner_key, *default)

    def popitem(self) -> Any:
        self._authorize()
        return super().popitem()

    def __reduce__(self) -> Any:
        # Serialize as a plain dict; guards are re-established on restore.
        return (dict, (unwrap_value(self),))


class ProtectedList(ProtectedContainer, list):
    """A ``list`` nested under a protected field that enforces scope on writes."""

    def __init__(self, data: list, key: str, check: ScopeChecker) -> None:
        super().__init__(wrap_value(item, key, check) for item in data)
        self._bind(key, check)

    def _guarded_children(self):
        return list(self)

    def __setitem__(self, index: Any, value: Any) -> None:
        self._authorize()
        super().__setitem__(
            index, wrap_value(value, self._protected_key, self._check)
        )

    def __delitem__(self, index: Any) -> None:
        self._authorize()
        super().__delitem__(index)

    def append(self, value: Any) -> None:
        self._authorize()
        super().append(wrap_value(value, self._protected_key, self._check))

    def extend(self, iterable: Any) -> None:
        self._authorize()
        super().extend(
            wrap_value(item, self._protected_key, self._check) for item in iterable
        )

    def insert(self, index: Any, value: Any) -> None:
        self._authorize()
        super().insert(
            index, wrap_value(value, self._protected_key, self._check)
        )

    def remove(self, value: Any) -> None:
        self._authorize()
        super().remove(value)

    def pop(self, *index: Any) -> Any:
        self._authorize()
        return super().pop(*index)

    def clear(self) -> None:
        self._authorize()
        super().clear()

    def sort(self, *args: Any, **kwargs: Any) -> None:
        self._authorize()
        super().sort(*args, **kwargs)

    def reverse(self) -> None:
        self._authorize()
        super().reverse()

    def __iadd__(self, other: Any) -> ProtectedList:
        self._authorize()
        super().__iadd__(
            wrap_value(item, self._protected_key, self._check) for item in other
        )
        return self

    def __reduce__(self) -> Any:
        # Serialize as a plain list; guards are re-established on restore.
        return (list, (unwrap_value(self),))


class ProtectedSet(ProtectedContainer, set):
    """A ``set`` nested under a protected field that enforces scope on writes."""

    def __init__(self, data: set, key: str, check: ScopeChecker) -> None:
        super().__init__(data)
        self._bind(key, check)

    def _guarded_children(self):
        # Set members must be hashable, hence never mutable containers.
        return ()

    def add(self, value: Any) -> None:
        self._authorize()
        super().add(value)

    def discard(self, value: Any) -> None:
        self._authorize()
        super().discard(value)

    def remove(self, value: Any) -> None:
        self._authorize()
        super().remove(value)

    def pop(self) -> Any:
        self._authorize()
        return super().pop()

    def clear(self) -> None:
        self._authorize()
        super().clear()

    def update(self, *others: Any) -> None:
        self._authorize()
        super().update(*others)

    def intersection_update(self, *others: Any) -> None:
        self._authorize()
        super().intersection_update(*others)

    def difference_update(self, *others: Any) -> None:
        self._authorize()
        super().difference_update(*others)

    def symmetric_difference_update(self, other: Any) -> None:
        self._authorize()
        super().symmetric_difference_update(other)

    def __reduce__(self) -> Any:
        # Serialize as a plain set; guards are re-established on restore.
        return (set, (unwrap_value(self),))
