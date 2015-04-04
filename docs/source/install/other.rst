.. _other-dependencies:

==================
Other Dependencies
==================
nymphemeral will be ready for use after installation via either of
the two methods described in :ref:`main-dependencies`. However, you
should install the following dependencies to be able to use all of
its features.

Mixmaster
---------
Follow the `Mixmaster instructions`_ to get `Mixmaster`_ running.
**Make sure you have** `OpenSSL`_ **1.0.1g or later.** If your
*Mixmaster* configuration is located anywhere other than the default
``~/Mix`` directory, you should edit
``~/.config/nymphemeral/nymphemeral.cfg`` to point to your
configuration.

.. _newsserver:

News Server
-----------
*aampy*'s default news server configured in ``nymphemeral.cfg`` is
set to ``localhost``, port ``119``. This default is useful if you use
`stunnel`_ to encrypt the connection between ``localhost:119`` and
your actual news server. If you want to connect directly to the news
server, you should edit ``nymphemeral.cfg`` and change the address
and port of the news server appropriately. Unfortunately, the
**python 2.7 nntplib** module does not support connections over
SSL/TLS.

**Optional:** you can use `Tor`_ along with *aampy* and *Mixmaster*.
An example `stunnel`_ configuration, useful for encrypting your news
feed, is located in ``/usr/share/nymphemeral/connections``. There
is also sample `socat`_ scripts for tunneling messages and news
downloads via *Tor*.

.. _`mixmaster instructions`: https://anemone.mooo.com/mixmaster.html
.. _`openssl`: https://www.openssl.org
.. _`socat`: http://www.dest-unreach.org/socat
.. _`stunnel`: https://www.stunnel.org
.. _`tor`: https://www.torproject.org
