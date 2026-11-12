"""Demonstrate what SESSION_USE_SIGNER actually covers.

Run from the repository root:
    .venv/bin/python -m security.session-integrity.demo_01_signer_scope
(importing a hyphenated path is handled by run_demos.sh)
"""

import sys
import warnings
from pathlib import Path

import flask
import msgspec

warnings.simplefilter("ignore")
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_storage import FakeStorage, FakeStorageSessionInterface  # noqa: E402


def make_app(storage: FakeStorage, use_signer: bool) -> flask.Flask:
    app = flask.Flask(__name__)
    app.secret_key = "app-secret-key"
    app.config["SESSION_TYPE"] = "cachelib"  # value irrelevant, interface set below
    app.config["SESSION_SERIALIZATION_FORMAT"] = "msgpack"

    interface = FakeStorageSessionInterface(
        app, storage=storage, use_signer=use_signer
    )
    app.session_interface = interface

    @app.route("/set", methods=["POST"])
    def set_value():
        flask.session["value"] = flask.request.form["value"]
        return "value set"

    @app.route("/get")
    def get_value():
        return flask.session.get("value", "no value set")

    return app


def main() -> None:
    storage = FakeStorage()
    app = make_app(storage, use_signer=True)
    client = app.test_client()

    print("== 1. write a session through the real save_session path ==")
    client.post("/set", data={"value": "user=alice; role=user"})
    cookie = client.get_cookie(app.config["SESSION_COOKIE_NAME"])
    print(f"cookie value          : {cookie.value}")
    print("  (itsdangerous format '<sid>.<timestamp>.<HMAC>'; the signature is")
    print("   computed over the sid string carried by the COOKIE only)")

    storage_key = next(iter(storage.records))
    raw = storage.raw_get(storage_key)
    print(f"\nstorage key            : {storage_key}")
    print(f"stored bytes (msgpack) : {raw!r}")
    print(f"decoded payload        : {msgspec.msgpack.decode(raw)}")
    print("  -> no signature, no sid binding, no namespace/version marker")

    print("\n== 2. tamper with the stored record directly ==")
    tampered = msgspec.msgpack.encode({"value": "user=alice; role=admin"})
    storage.raw_set(storage_key, tampered)
    rv = client.get("/get")
    print(f"attacker rewrote role -> app now reads: {rv.data.decode()!r}")
    assert rv.data == b"user=bob; role=user" or rv.data == b"user=alice; role=admin"

    print("\n== 3. swap whole records between two sessions ==")
    client2 = app.test_client()
    client2.post("/set", data={"value": "user=bob; role=user"})
    key_b = next(k for k in storage.records if k != storage_key)
    # alice keeps her signed cookie; only the backend record is replaced
    storage.raw_set(storage_key, storage.raw_get(key_b))
    rv = client.get("/get")
    print(f"after swap, alice's cookie loads bob's data: {rv.data.decode()!r}")
    assert rv.data == b"user=bob; role=user"

    print("\n== 4. what the cookie signature DOES catch ==")
    client3 = app.test_client()
    client3.set_cookie(app.config["SESSION_COOKIE_NAME"], "forged.abc.def")
    rv = client3.get("/get")
    print(f"forged cookie -> BadSignature -> fresh empty session, /get={rv.data!r}")
    assert rv.data == b"no value set"

    print(
        "\nConclusion: SESSION_USE_SIGNER authenticates the sid inside the cookie.\n"
        "The stored session body carries no MAC: an attacker with write access to\n"
        "storage can mutate it or move it between sids, and the app accepts it."
    )


if __name__ == "__main__":
    main()
