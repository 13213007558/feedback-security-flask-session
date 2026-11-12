"""End-to-end demo: the same attacks against the integrity-protected storage.

Run from the repository root:
    .venv/bin/python security/session-integrity/demo_02_protected.py
"""

import logging
import sys
import warnings
from pathlib import Path

import flask
import msgspec

warnings.simplefilter("ignore")
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_storage import FakeStorage  # noqa: E402
from integrity import KeyRing, SigningKey  # noqa: E402
from protected_storage import ProtectedSessionInterface, ProtectedStorage  # noqa: E402

logging.disable(logging.CRITICAL)

NS = "billing-app"
FV = 1


def make_app(storage: FakeStorage, keyring: KeyRing, namespace: str = NS, fv: int = FV):
    app = flask.Flask(__name__)
    app.secret_key = "app-secret-key"
    protected = ProtectedStorage(storage, keyring, namespace=namespace, format_version=fv)
    app.session_interface = ProtectedSessionInterface(
        app, storage=storage, protected=protected, use_signer=True
    )

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
    keyring = KeyRing(SigningKey(kid="k1", secret=b"hmac-secret"))
    app = make_app(storage, keyring)
    client = app.test_client()

    print("== 1. normal write/read through Flask still works ==")
    client.post("/set", data={"value": "user=alice; role=user"})
    assert client.get("/get").data == b"user=alice; role=user"
    key = next(iter(storage.records))
    envelope = msgspec.msgpack.decode(storage.raw_get(key))
    print(f"stored envelope fields: {sorted(envelope)}")
    print(f"  sid={envelope['sid']!r} ns={envelope['ns']!r} fv={envelope['fv']}"
          f" kid={envelope['kid']!r} exp={envelope['exp']}")
    print(f"  payload still plaintext: {envelope['payload']!r}")

    print("\n== 2. direct payload tamper is rejected ==")
    envelope["payload"] = msgspec.msgpack.encode({"value": "role=admin"})
    storage.raw_set(key, msgspec.msgpack.encode(envelope))
    rv = client.get("/get")
    print(f"  /get after tamper -> {rv.data!r} (fresh session, tamper rejected)")
    assert rv.data == b"no value set"

    print("\n== 3. record swap between sids is rejected ==")
    storage2 = FakeStorage()
    app2 = make_app(storage2, keyring)
    bob = app2.test_client()
    bob.post("/set", data={"value": "user=bob"})
    bob_key = next(iter(storage2.records))
    # plant bob's valid envelope under alice's key
    storage.raw_set(key, storage2.raw_get(bob_key))
    rv = client.get("/get")
    print(f"  /get after swap -> {rv.data!r} (sid binding mismatch)")
    assert rv.data == b"no value set"

    print("\n== 4. record from another namespace is rejected ==")
    other_storage = FakeStorage()
    other_app = make_app(other_storage, keyring, namespace="checkout-app")
    other = other_app.test_client()
    other.post("/set", data={"value": "evil"})
    other_key = next(iter(other_storage.records))
    storage.raw_set(key, other_storage.raw_get(other_key))
    rv = client.get("/get")
    print(f"  /get after cross-namespace plant -> {rv.data!r}")
    assert rv.data == b"no value set"

    print("\n== 5. format version rollback/change is rejected ==")
    fv_storage = FakeStorage()
    fv_app = make_app(fv_storage, keyring, fv=99)
    fv_client = fv_app.test_client()
    fv_client.post("/set", data={"value": "v99"})
    fv_key = next(iter(fv_storage.records))
    storage.raw_set(key, fv_storage.raw_get(fv_key))
    rv = client.get("/get")
    print(f"  /get after foreign format version -> {rv.data!r}")
    assert rv.data == b"no value set"

    print("\n== 6. expired envelope is rejected ==")
    from integrity import seal
    expired = seal(
        sid=key.split(":", 1)[1],
        namespace=NS,
        format_version=FV,
        payload=msgspec.msgpack.encode({"value": "stale"}),
        keyring=keyring,
        ttl_seconds=10,
        now=1000,
    )
    storage.raw_set(key, expired)
    rv = client.get("/get")
    print(f"  /get with expired record -> {rv.data!r}")
    assert rv.data == b"no value set"

    print("\n== 7. key rotation then retirement (fresh app) ==")
    rot_storage = FakeStorage()
    ring = KeyRing(SigningKey(kid="k1", secret=b"hmac-secret"))
    rot_app = make_app(rot_storage, ring)
    rot_client = rot_app.test_client()
    rot_client.post("/set", data={"value": "before-rotation"})
    rot_key = next(iter(rot_storage.records))
    legacy_envelope = rot_storage.raw_get(rot_key)
    assert msgspec.msgpack.decode(legacy_envelope)["kid"] == "k1"

    # rotate: k1 stays in the ring for verification, k2 becomes the signer
    ring.rotate(SigningKey(kid="k2", secret=b"new-hmac-secret"))
    assert rot_client.get("/get").data == b"before-rotation"
    rot_client.post("/set", data={"value": "after-rotation"})
    assert msgspec.msgpack.decode(rot_storage.raw_get(rot_key))["kid"] == "k2"
    print("  rotation: old record still verifies, new records use kid='k2'")

    # retire k1: pre-rotation envelopes are now refused outright
    ring.keys["k1"] = SigningKey(kid="k1", secret=b"hmac-secret", retired=True)
    rot_storage.raw_set(rot_key, legacy_envelope)
    rv = rot_client.get("/get")
    print(f"  legacy envelope after k1 retirement -> {rv.data!r}")
    assert rv.data == b"no value set"

    print(
        "\nAll attacks rejected. Note the payload in step 1 is plaintext:\n"
        "this is integrity/authenticity, not confidentiality."
    )


if __name__ == "__main__":
    main()
