import pickle

import flask
import pytest
from cachelib import SimpleCache
from flask_session import Session
from flask_session.base import (
    MsgSpecSerializer,
    ServerSideSessionInterface,
    SessionDeserializationError,
    _is_safe_legacy_pickle,
)
from flask_session.migration import (
    TrustedSessionRecord,
    migrate_trusted_sessions,
)

LEGACY_SAMPLE = pickle.dumps({"value": "legacy", "_permanent": False})


class SerializedMemoryInterface(ServerSideSessionInterface):
    """Small test backend that exercises the serializer on every read/write."""

    ttl = True

    def __init__(self, app, store=None, **kwargs):
        self.store = {} if store is None else store
        super().__init__(app, **kwargs)

    def _retrieve_session_data(self, store_id):
        payload = self.store.get(store_id)
        if payload is None:
            return None
        return self.serializer.loads(payload)

    def _delete_session(self, store_id):
        self.store.pop(store_id, None)

    def _upsert_session(self, session_lifetime, session, store_id):
        self.store[store_id] = self.serializer.dumps(dict(session))


def create_app(allow_pickle_fallback=False):
    app = flask.Flask(__name__)
    app.testing = True
    app.config.update({"SESSION_PERMANENT": False})
    interface = SerializedMemoryInterface(
        app,
        serialization_format="json",
        allow_pickle_fallback=allow_pickle_fallback,
    )

    @app.route("/set", methods=["POST"])
    def set_value():
        flask.session["value"] = flask.request.form["value"]
        return "set"

    @app.route("/get")
    def get_value():
        return flask.session.get("value", "missing")

    app.session_interface = interface
    return app


def request_with_sid(client, sid, path="/get"):
    client.set_cookie("session", sid)
    return client.get(path)


class DecoderSpy:
    def __init__(self, result=None, error=None):
        self.calls = []
        self.result = result
        self.error = error

    def __call__(self, payload):
        self.calls.append(payload)
        if self.error is not None:
            raise self.error
        return self.result


def test_config_switch_defaults_off_and_can_be_enabled():
    app = flask.Flask(__name__)
    app.config.update({"SESSION_TYPE": "cachelib", "SESSION_CACHELIB": SimpleCache()})
    Session(app)
    assert app.session_interface.serializer.allow_pickle_fallback is False

    app = flask.Flask(__name__)
    app.config.update(
        {
            "SESSION_TYPE": "cachelib",
            "SESSION_CACHELIB": SimpleCache(),
            "SESSION_ALLOW_PICKLE_FALLBACK": True,
        }
    )
    Session(app)
    assert app.session_interface.serializer.allow_pickle_fallback is True


def test_default_rejects_legacy_pickle_without_using_legacy_decoder():
    app = create_app()
    spy = DecoderSpy(result={"value": "should not be used"})
    interface = app.session_interface
    interface.serializer.legacy_decoder = spy
    interface.store["session:legacy-sid"] = LEGACY_SAMPLE

    with pytest.raises(SessionDeserializationError):
        interface.serializer.loads(LEGACY_SAMPLE)

    assert spy.calls == []

    # A request fails closed to a fresh session and leaves the record intact.
    response = request_with_sid(app.test_client(), "legacy-sid")
    assert response.data == b"missing"
    assert interface.store["session:legacy-sid"] == LEGACY_SAMPLE
    assert spy.calls == []


def test_opt_in_uses_legacy_decoder_for_plain_dict_sample():
    app = create_app(allow_pickle_fallback=True)
    interface = app.session_interface
    spy = DecoderSpy(result={"value": "legacy", "_permanent": False})
    interface.serializer.legacy_decoder = spy
    interface.store["session:legacy-sid"] = LEGACY_SAMPLE

    client = app.test_client()
    response = request_with_sid(client, "legacy-sid")

    assert response.data == b"legacy"
    assert spy.calls == [LEGACY_SAMPLE]

    # A normal save converts the legacy record to the configured safe format.
    client.post("/set", data={"value": "updated"})
    stored = interface.store["session:legacy-sid"]
    assert interface.serializer.loads(stored)["value"] == "updated"
    assert not _is_safe_legacy_pickle(stored)


def test_corrupt_new_format_does_not_fall_back_to_legacy_decoder():
    app = create_app(allow_pickle_fallback=True)
    interface = app.session_interface
    spy = DecoderSpy(result={"value": "unexpected"})
    interface.serializer.legacy_decoder = spy
    corrupt = b'{"value": "truncated"'
    interface.store["session:corrupt-sid"] = corrupt

    with pytest.raises(SessionDeserializationError):
        interface.serializer.loads(corrupt)

    assert spy.calls == []

    response = request_with_sid(app.test_client(), "corrupt-sid")
    assert response.data == b"missing"
    assert interface.store["session:corrupt-sid"] == corrupt
    assert spy.calls == []


def test_opt_in_still_rejects_pickle_requiring_imports_without_execution():
    # A pickle that requires a class import. It is never unpickled by the
    # test; the serializer's preflight must reject it before any call.
    unsafe_payload = (
        b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x8c\x05tests\x94\x8c\x05Unsafe\x94\x93\x94."
    )
    app = create_app(allow_pickle_fallback=True)
    spy = DecoderSpy(result={"value": "unexpected"})

    serializer = MsgSpecSerializer(
        app,
        "json",
        allow_pickle_fallback=True,
        legacy_decoder=spy,
    )
    with pytest.raises(SessionDeserializationError):
        serializer.loads(unsafe_payload)

    assert spy.calls == []


def test_safe_format_rejects_non_dict_payload():
    app = create_app()
    serializer = app.session_interface.serializer

    with pytest.raises(SessionDeserializationError):
        serializer.loads(b'["not", "a", "dict"]')


def test_migration_uses_plain_dict_sample_and_returns_safe_value():
    app = create_app()
    serializer = app.session_interface.serializer
    spy = DecoderSpy(result={"value": "legacy", "_permanent": False})

    report = migrate_trusted_sessions(
        [TrustedSessionRecord("session:legacy-sid", LEGACY_SAMPLE)],
        serializer=serializer,
        legacy_decoder=spy,
    )

    assert len(report.results) == 1
    result = report.results[0]
    assert result.migrated
    assert spy.calls == [LEGACY_SAMPLE]
    assert serializer.loads(result.value) == {"value": "legacy", "_permanent": False}


def test_migration_failure_keeps_original_record_and_does_not_write():
    app = create_app()
    interface = app.session_interface
    spy = DecoderSpy(error=RuntimeError("legacy decoder unavailable"))
    interface.store["session:legacy-sid"] = LEGACY_SAMPLE

    report = migrate_trusted_sessions(
        [("session:legacy-sid", LEGACY_SAMPLE)],
        serializer=interface.serializer,
        legacy_decoder=spy,
    )

    assert len(report.failed) == 1
    assert report.failed[0].original == LEGACY_SAMPLE
    assert report.failed[0].value is None
    assert interface.store["session:legacy-sid"] == LEGACY_SAMPLE


def test_migration_rejects_unsafe_payload_without_calling_legacy_decoder():
    app = create_app()
    serializer = app.session_interface.serializer
    spy = DecoderSpy(result={"value": "unexpected"})
    unsafe_payload = (
        b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x8c\x05tests\x94\x8c\x05Unsafe\x94\x93\x94."
    )

    report = migrate_trusted_sessions(
        [("session:unsafe", unsafe_payload)],
        serializer=serializer,
        legacy_decoder=spy,
    )

    assert report.results[0].status == "failed"
    assert report.results[0].original == unsafe_payload
    assert spy.calls == []


def test_migration_accepts_mapping_and_retains_originals():
    app = create_app()
    serializer = app.session_interface.serializer
    spy = DecoderSpy(result={"value": "legacy", "_permanent": False})

    report = migrate_trusted_sessions(
        {"session:legacy-sid": LEGACY_SAMPLE},
        serializer=serializer,
        legacy_decoder=spy,
    )

    assert report.results[0].key == "session:legacy-sid"
    assert report.results[0].source == LEGACY_SAMPLE
    assert report.results[0].converted == report.results[0].value


def test_migration_failure_keeps_original_when_conversion_round_trip_fails():
    class FailingSerializer:
        def __init__(self):
            self.dumps_calls = 0

        def dumps(self, data):
            self.dumps_calls += 1
            raise TypeError("unsupported value in converted session")

        def loads(self, data):
            raise AssertionError("loads must not run after dumps fails")

    app = create_app()
    serializer = FailingSerializer()
    payload = pickle.dumps({"value": "legacy", "_permanent": False})

    report = migrate_trusted_sessions(
        [("session:unsupported", payload)],
        serializer=serializer,
    )

    assert report.results[0].status == "failed"
    assert report.results[0].original == payload
    assert report.results[0].value is None
    assert report.results[0].error
    assert serializer.dumps_calls == 1
    assert app.session_interface.store.get("session:unsupported") is None


def test_opt_in_rejects_payload_with_trailing_bytes():
    app = create_app(allow_pickle_fallback=True)
    spy = DecoderSpy(result={"value": "unexpected"})
    serializer = MsgSpecSerializer(
        app,
        "json",
        allow_pickle_fallback=True,
        legacy_decoder=spy,
    )

    with pytest.raises(SessionDeserializationError):
        serializer.loads(LEGACY_SAMPLE + b"trailing")

    assert spy.calls == []


def test_online_request_still_works_after_successful_migration():
    app = create_app()
    interface = app.session_interface
    interface.store["session:legacy-sid"] = LEGACY_SAMPLE

    report = migrate_trusted_sessions(
        [("session:legacy-sid", LEGACY_SAMPLE)],
        serializer=interface.serializer,
    )
    assert report.results[0].migrated

    # The caller performs the write only for a successful conversion.
    interface.store["session:legacy-sid"] = report.migrated_values[
        "session:legacy-sid"
    ]

    response = request_with_sid(app.test_client(), "legacy-sid")
    assert response.data == b"legacy"
