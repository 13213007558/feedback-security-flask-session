Serialization
------------------------------------

.. warning::

    Online session reads use safe serialization by default. Historical pickle
    records are rejected unless the explicit compatibility switch described
    below is enabled, and the switch only accepts inert plain-dictionary
    payloads. Prefer the offline migration path for trusted legacy data.

From 0.7.0 the serializer is msgspec. The format it uses is configurable with ``SESSION_SERIALIZATION_FORMAT``. The default format is ``'msgpack'`` which has 30% storage reduction compared to ``'json'``. The ``'json'`` format may be helpful for debugging, easier viewing or compatibility. Switching between the two should be seamless, even for existing sessions.

.. _legacy-pickle:

Historical pickle records
~~~~~~~~~~~~~~~~~~~~~~~~~

Online reads are safe-format-only by default. The serializer accepts the
configured ``SESSION_SERIALIZATION_FORMAT`` and its msgspec alternate. It does
**not** retry an undecodable value with ``pickle``. A stored record that cannot
be read is left in place, and the current request proceeds with a fresh session
so an operator can migrate or inspect the record offline.

There are two supported paths for legacy records:

1. **Offline migration (recommended).** Read records from storage with your own
   trusted tooling, then pass them explicitly to
   :func:`flask_session.migration.migrate_trusted_sessions`. That function only
   processes the records you provide, verifies each one without executing it,
   and returns safe-format values. It does not write to or delete from storage,
   so a failed record remains available for retry.
2. **Temporary online compatibility window.** Set
   ``SESSION_ALLOW_PICKLE_FALLBACK = True`` (or pass
   ``allow_pickle_fallback=True`` to a session interface). Only structurally
   inert plain-dictionary pickles are accepted, and the record is rewritten in
   the configured safe format the next time that session is saved. Disable this
   setting once the legacy records have drained.

Neither path accepts arbitrary pickle objects: payloads that could import
names, call code, or restore persistent objects are rejected before the legacy
decoder is called. Do not treat the compatibility switch as a general-purpose
pickle loader.

Migration example:

.. code-block:: python

    from flask_session.migration import migrate_trusted_sessions

    legacy_records = [
        ("session:<sid>", legacy_bytes),
        # ... only records you have explicitly obtained and trusted
    ]

    report = migrate_trusted_sessions(
        legacy_records,
        serializer=app.session_interface.serializer,
    )

    for failure in report.failed:
        print(failure.key, failure.error)  # original payload is retained

    # Persist only successful conversions with your storage client.
    for key, value in report.migrated_values.items():
        storage_client.set(key, value)

The msgspec library has speed and memory advantages over other libraries. However, if you want to use a different library (such as pickle or orjson), you can override the :attr:`session_interface.serializer`.

If you encounter a TypeError such as: "Encoding objects of type <type> is unsupported", you may be attempting to serialize an unsupported type. In this case, you can either convert the object to a supported type or use a different serializer.

Casting to a supported type:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    session["status"] = str(LazyString('done')))


.. note::

    Flask's flash method uses the session to store messages so you must also pass supported types to the flash method.


For a detailed list of supported types by the msgspec serializer, please refer to the official documentation at `msgspec supported types <https://jcristharif.com/msgspec/supported-types.html>`_.

Overriding the serializer:
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    from flask_session import Session
    import orjson

    app = Flask(__name__)
    Session(app)

    # Override the serializer
    app.session_interface.serializer = orjson

Any serializer that has a ``dumps`` and ``loads`` method can be used.