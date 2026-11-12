.. currentmodule:: flask_session

Security
==========

.. warning::

  Flask is a micro-framework and does not provide all security features out of the box. It is important to configure security settings for your application.
  
Flask configuration
--------------------

Please refer to documentation for `Flask`_, `OWASP`_, and other resources such as `MDN`_ for the latest information on best practice.

Consider the following Flask configurations in production:

.. list-table::
   :header-rows: 1
   :align: left

   * - Setting
     - Consideration
   * - SESSION_COOKIE_SECURE
     - Set to ``True`` if your application is served over HTTPS.
   * - SESSION_COOKIE_NAME
     - Use ``__Secure-`` or ``__Host-`` prefix according to MDN docs.
   * - SESSION_COOKIE_SAMESITE
     - Use ``Lax`` or ``Strict``

You can use a security plugin such as `Flask-Talisman`_ to set these and more.

Storage
------------------

Take care to secure your storage and storage client connection. For example, setup SSL/TLS and storage authentication.
  

Session fixation
------------------

Session fixation is an attack that permits an attacker to hijack a valid user session. The attacker can fixate a user's session by providing them with a session identifier. The attacker can then use the session identifier to impersonate the user.
As one tool among others that can mitigate session fixation, is regenerating the session identifier when a user logs in. This can be done by calling the :meth:`flask.Flask.session_interface.regenerate` method. This method is defined in :class:`flask_session.base.ServerSideSession`.

.. code-block:: python

    @app.route('/login')
    def login():
        # your login logic ...
        app.session_interface.regenerate(session)
        # your response ...

The method always rotates the identifier, including when the session is
currently empty. This supports flows that clear anonymous data first, rotate,
and then write the authenticated identity. Calling it multiple times in one
request produces a new identifier each time and removes every earlier record.

Rotation removes the previous record and verifies that the old identifier can
no longer load session data. A reported deletion failure, a raised storage error,
or a record that is still readable causes
:class:`flask_session.base.SessionRegenerationError`. The method assigns a fresh
identifier before raising as well, so an application that catches the error does
not persist the new identity under the old identifier. The response is then
refused by ``save_session`` instead of issuing a cookie for a rotation that did
not complete.

There is an unavoidable window between deleting the old record and saving the
new one. If saving fails, the response fails and neither the old identifier nor
the rejected new one can load the new identity; the user must log in again.

.. _Flask: https://flask.palletsprojects.com/en/2.3.x/security/#set-cookie-options
.. _MDN: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
.. _OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
.. _Flask-Talisman: https://github.com/wntrblm/flask-talisman