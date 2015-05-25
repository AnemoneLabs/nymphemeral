.. _newsserver:

===========
News Server
===========
*aampy* is the tool underneath nymphemeral that downloads messages
sent to your nym via a news server. The default news server
configured in ``nymphemeral.cfg`` is set to ``localhost``, port
``119``. This default is useful if you use `stunnel`_ to encrypt the
connection between ``localhost:119`` and your actual news server.
If you followed :ref:`Connections`, you do not need to configure
anything.

**nymphemeral should be ready to tunnel your news feed via Tor!**

If you want to connect directly to the news server, you should edit
``nymphemeral.cfg`` and change the address and port of the news
server appropriately. Unfortunately, the **python 2.7 nntplib**
module does not support connections over SSL/TLS.

.. _`stunnel`: https://www.stunnel.org
