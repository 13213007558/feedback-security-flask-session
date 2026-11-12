"""Capability audit for the bundled session backends.

The batch cleanup guarantee can only be enabled where the storage engine
provides every primitive in :class:`~flask_session.cleanup.contract.StoreCapabilities`.
This module records, for each bundled backend, whether it relies on native TTL
and, for the non-TTL engines, which primitives are missing.

A backend that cannot satisfy the contract must be rejected
(:class:`UnsafeCleanupError`) rather than silently run an unsafe sweep.
"""

from .contract import (
    BackendCleanupAssessment,
    StoreCapabilities,
    UnsafeCleanupError,
)

# Backends whose storage engine expires records natively.  They must not be put
# behind a manual cleanup path at all: their TTL is the expiry guarantee.
_NATIVE_TTL_BACKENDS = (
    "redis",
    "memcached",
    "filesystem",
    "cachelib",
    "mongodb",
    "dynamodb",
)

# Static capability matrix for engines without native TTL.  The primitives are
# evaluated against what the storage engine and the *current adapter* expose.
_BACKEND_CAPABILITIES = {
    # The relational engines themselves support every required primitive, but
    # the shipped adapters only implement unbounded bulk DELETE and never expose
    # a bounded scan or compare-and-delete, so the guarantee cannot be enabled
    # until those operations are added behind the BatchCleanupStore interface.
    "sqlalchemy": StoreCapabilities(
        bounded_scan=False,
        conditional_delete=False,
        monotonic_writes=True,
        value_isolated_scan=True,
    ),
    "postgresql": StoreCapabilities(
        bounded_scan=False,
        conditional_delete=False,
        monotonic_writes=True,
        value_isolated_scan=True,
    ),
}


def assess_backend(backend: str) -> BackendCleanupAssessment:
    """Return the cleanup assessment for one bundled backend name."""
    name = backend.lower()

    if name in _NATIVE_TTL_BACKENDS:
        return BackendCleanupAssessment(
            backend=name,
            native_ttl=True,
            capabilities=None,
            reason=(
                "Storage engine provides native TTL; manual batch cleanup is "
                "neither required nor permitted to run."
            ),
        )

    if name not in _BACKEND_CAPABILITIES:
        return BackendCleanupAssessment(
            backend=name,
            native_ttl=False,
            capabilities=None,
            reason="Unknown backend; no capability evidence available.",
        )

    capabilities = _BACKEND_CAPABILITIES[name]
    missing = capabilities.missing()
    if missing:
        reason = (
            "Missing required cleanup primitives: "
            + ", ".join(missing)
            + ". The guarantee must stay disabled until these are implemented."
        )
    else:
        reason = "Implements every required cleanup primitive."
    return BackendCleanupAssessment(
        backend=name,
        native_ttl=False,
        capabilities=capabilities,
        reason=reason,
    )


def all_assessments():
    """Assess every bundled backend in stable order."""
    return tuple(
        assess_backend(name)
        for name in (*_NATIVE_TTL_BACKENDS, *_BACKEND_CAPABILITIES)
    )


def ensure_cleanup_supported(backend: str) -> None:
    """Raise :class:`UnsafeCleanupError` unless cleanup may be enabled.

    Native-TTL backends are rejected from the manual path; non-TTL backends are
    rejected while any required primitive is missing.  This is the fail-closed
    gate an application should call before scheduling a sweep.
    """
    assessment = assess_backend(backend)
    if assessment.native_ttl:
        raise UnsafeCleanupError(
            f"Backend '{backend}' relies on native TTL and must not run manual cleanup."
        )
    if not assessment.eligible:
        raise UnsafeCleanupError(
            f"Backend '{backend}' cannot guarantee safe batch cleanup: {assessment.reason}"
        )
