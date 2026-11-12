"""Offline migration of explicitly trusted legacy session records.

The online session reader never falls back to pickle unless an application
opts in with ``SESSION_ALLOW_PICKLE_FALLBACK``. Applications that still have
legacy records can instead migrate a data set they have explicitly obtained
and trusted, without putting the unsafe decoder on the request path.

This module is deliberately side-effect free with respect to storage. It
accepts records supplied by the caller, returns newly encoded values, and
never deletes or overwrites an original record. Persisting a successful
result is the caller's responsibility; failed records remain untouched.
"""

from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Tuple,
    Union,
)

from itsdangerous import want_bytes

from .base import _default_legacy_pickle_decoder, _is_safe_legacy_pickle


class UnsafeLegacySessionRecord(ValueError):
    """Raised when a trusted record is not an inert plain-dict pickle."""


class TrustedSessionRecord:
    """A legacy record explicitly supplied by the caller as trusted.

    ``key`` identifies the storage record, while ``value`` is the stored
    serialized session. Records are never mutated or removed by this module.
    """

    __slots__ = ("key", "value")

    def __init__(self, key: str, value: bytes):
        self.key = key
        self.value = want_bytes(value)

    def __repr__(self) -> str:
        return f"TrustedSessionRecord(key={self.key!r})"

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, TrustedSessionRecord):
            return NotImplemented
        return self.key == other.key and self.value == other.value


RecordInput = Union[TrustedSessionRecord, Tuple[str, bytes]]


# A caller can provide an explicit mapping, a single record, or any iterable
# of records. There is deliberately no storage client or discovery argument.
RecordCollection = Union[
    Mapping[str, bytes], TrustedSessionRecord, Iterable[RecordInput]
]


@dataclass(frozen=True)
class MigrationResult:
    """Outcome for one supplied record.

    ``original`` always contains the caller's original payload, including on
    failure, so the caller can retain or retry it. ``value`` is only set when
    ``status`` is ``"migrated"`` and contains the safe-format replacement.
    """

    key: str
    status: str
    value: Optional[bytes] = None
    original: Optional[bytes] = None
    error: Optional[str] = None

    @property
    def migrated(self) -> bool:
        return self.status == "migrated"

    @property
    def converted(self) -> Optional[bytes]:
        """Alias for ``value``; only present for successful conversions."""
        return self.value

    @property
    def source(self) -> Optional[bytes]:
        """Alias for ``original``; always retains the caller's payload."""
        return self.original


@dataclass
class MigrationReport:
    """Results of an offline trusted-data migration."""

    results: List[MigrationResult] = field(default_factory=list)

    @property
    def migrated(self) -> List[MigrationResult]:
        return [result for result in self.results if result.migrated]

    @property
    def failed(self) -> List[MigrationResult]:
        return [result for result in self.results if not result.migrated]

    @property
    def migrated_values(self) -> Dict[str, bytes]:
        """Safe-format values ready for the caller to persist."""
        return {result.key: result.value for result in self.migrated}

    def __iter__(self):
        return iter(self.results)

    def __len__(self) -> int:
        return len(self.results)


def _coerce_record(record: RecordInput) -> TrustedSessionRecord:
    if isinstance(record, TrustedSessionRecord):
        return record
    if isinstance(record, tuple) and len(record) == 2:
        key, value = record
        return TrustedSessionRecord(key=key, value=value)
    raise TypeError(
        "Each record must be TrustedSessionRecord or a (key, value) tuple"
    )


def _iter_records(records: RecordCollection) -> Iterable[RecordInput]:
    """Yield only the records explicitly supplied by the caller."""
    if isinstance(records, TrustedSessionRecord):
        return [records]
    if isinstance(records, Mapping):
        return [(key, value) for key, value in records.items()]
    if (
        isinstance(records, tuple)
        and len(records) == 2
        and isinstance(records[0], str)
    ):
        return [records]
    return records


def migrate_trusted_sessions(
    records: RecordCollection,
    serializer: Any,
    legacy_decoder: Optional[Callable[[bytes], Any]] = None,
) -> MigrationReport:
    """Convert caller-supplied trusted pickle records to the safe format.

    Only the records explicitly passed in are considered. No storage client is
    accepted, so this function cannot discover or delete other records. Each
    record is decoded with the legacy decoder only after a non-executing
    ``pickletools`` check confirms it is an inert plain-dict payload. The
    result must be a plain ``dict`` with string keys, and the safe serializer
    must be able to encode and read it back before the conversion is reported
    as successful.

    Failures are isolated per record and reported in
    :attr:`MigrationReport.failed`; the original payload remains in
    :attr:`MigrationResult.original`.

    :param records: An explicitly trusted collection: a ``{key: value}``
    mapping, a single :class:`TrustedSessionRecord`, or an iterable of
    :class:`TrustedSessionRecord` objects or ``(key, value)`` pairs.
    :param serializer: A serializer with ``dumps`` and ``loads`` methods, for
    example :class:`flask_session.base.MsgSpecSerializer`. Its ``loads``
    method is used to verify the converted record is readable.
    :param legacy_decoder: Optional replacement for the legacy pickle decoder.
    It is called only after the structural safety check. This is useful for
    offline tooling and tests that must observe decoder calls.
    """
    decode_legacy = legacy_decoder or _default_legacy_pickle_decoder
    report = MigrationReport()

    for raw_record in _iter_records(records):
        record = _coerce_record(raw_record)
        original = record.value
        try:
            if not _is_safe_legacy_pickle(original):
                raise UnsafeLegacySessionRecord(
                    "Record is not an inert plain-dict pickle"
                )

            decoded = decode_legacy(original)
            if not isinstance(decoded, dict):
                raise UnsafeLegacySessionRecord(
                    "Legacy session payload did not decode to a dict"
                )
            if any(not isinstance(key, str) for key in decoded):
                raise UnsafeLegacySessionRecord(
                    "Legacy session payload contains a non-string key"
                )

            converted = serializer.dumps(decoded)
            # Verify the replacement before describing it as migrated.
            if serializer.loads(converted) != decoded:
                raise ValueError("Converted session did not round-trip")
        except Exception as exc:
            report.results.append(
                MigrationResult(
                    key=record.key,
                    status="failed",
                    original=original,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
        else:
            report.results.append(
                MigrationResult(
                    key=record.key,
                    status="migrated",
                    value=converted,
                    original=original,
                )
            )

    return report


# Convenient spellings for callers thinking in terms of the storage format.
migrate_trusted_pickle_records = migrate_trusted_sessions
migrate_legacy_sessions = migrate_trusted_sessions
