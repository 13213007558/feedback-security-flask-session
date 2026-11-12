class FlaskSessionException(Exception):
    """Base class for all exceptions raised by Flask-Session."""


class ProtectedFieldError(PermissionError, FlaskSessionException):
    """Raised when a write to a protected session field is attempted without
    the required scope.

    The mutation is refused before any state changes are applied, so the
    session keeps its previous, internally consistent state.

    :param key: The protected session field that was targeted.
    :param required_scopes: Scopes authorized to write the field.
    :param active_scopes: Scopes active on the session for the current request.
    """

    def __init__(
        self,
        key: str,
        required_scopes: frozenset,
        active_scopes: frozenset,
    ) -> None:
        self.key = key
        self.required_scopes = frozenset(required_scopes)
        self.active_scopes = frozenset(active_scopes)
        missing = sorted(self.required_scopes - self.active_scopes)
        super().__init__(
            f"Refusing write to protected session field {key!r}: "
            f"requires one of scope {sorted(self.required_scopes)}, "
            f"active scopes are {sorted(self.active_scopes)}, missing {missing}."
        )
