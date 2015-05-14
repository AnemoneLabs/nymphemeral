.. _newsserver:

===========
News Server
===========
*aampy* is the tool (underneath nymphemeral) that downloads messages
(sent to your nym) via a news server. If you do not have one running,
we recommend using :ref:`tor-socat-stunnel` for that. If you followed
the :ref:`mixmaster` instructions, you already have them installed
and running. You just need to do a similar process we did for the
SMTP script, but this time, we are going to copy ``socnews.sh``::

    cp /usr/share/nymphemeral/connections/socnews.sh ~

Enable it to be executed::

    chmod +x ~/socnews.sh

And finally, run it::

    cd
    ./socnews.sh

**Note:** This script will have to be executed every time the system
starts up.

Configuring
-----------
The default news server configured in ``nymphemeral.cfg``
is set to ``localhost``, port ``119``. This default is useful if you
use `stunnel`_ to encrypt the connection between ``localhost:119``
and your actual news server. If you followed the previous
instructions, you do not need to configure anything.

**nymphemeral should be ready to tunnel your news feed via Tor!**

If you want to connect directly to the news server, you should edit
``nymphemeral.cfg`` and change the address and port of the news
server appropriately. Unfortunately, the **python 2.7 nntplib**
module does not support connections over SSL/TLS.

.. _`stunnel`: https://www.stunnel.org
