.. _newsserver:

===========
News Server
===========
**Zax-type** nym servers deliver messages to their nyms by posting
them on a news group. `aampy`_ is the tool underneath nymphemeral that
downloads those messages via a news server. The default news server
configured in ``nymphemeral.cfg`` is set to ``localhost``, port
``119``. This default is useful if you use `stunnel`_ to encrypt the
connection between ``localhost:119`` and your actual news server,
exactly what was done on :ref:`Connections`. If you followed that
section, you do not need to configure anything.

.. note::

    nymphemeral should be ready to tunnel your news feed via Tor!

If you want to connect directly to the news server, you should edit
``nymphemeral.cfg`` and change the address and port of the news
server appropriately. Unfortunately, the **python 2.7 nntplib**
module does not support connections over SSL/TLS.

.. _`aampy`: https://github.com/rxcomm/aampy
.. _`stunnel`: https://www.stunnel.org
