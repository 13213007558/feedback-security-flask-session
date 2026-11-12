API
---

Anything documented here is part of the public API that Flask-Session provides, unless otherwise indicated. Anything not documented here is considered internal or private and may change at any time.


.. module:: flask_session

.. autoclass:: Session
   :members: init_app

.. autoclass:: flask_session.base.ServerSideSession

.. autoclass:: flask_session.base.ServerSideSessionInterface
   :members: regenerate

.. autoclass:: flask_session.redis.RedisSessionInterface
.. autoclass:: flask_session.memcached.MemcachedSessionInterface
.. autoclass:: flask_session.filesystem.FileSystemSessionInterface
.. autoclass:: flask_session.cachelib.CacheLibSessionInterface
.. autoclass:: flask_session.migration.CutoverSessionInterface
   :members: set_phase
.. autoclass:: flask_session.migration.CutoverError
.. autoclass:: flask_session.migration.AuthorityUnconfirmed
.. autofunction:: flask_session.migration.register_cutover_error_handlers
.. autoclass:: flask_session.mongodb.MongoDBSessionInterface
.. autoclass:: flask_session.sqlalchemy.SqlAlchemySessionInterface
.. autoclass:: flask_session.dynamodb.DynamoDBSessionInterface
.. autoclass:: flask_session.postgresql.PostgreSqlSessionInterface