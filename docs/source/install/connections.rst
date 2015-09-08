.. _connections:

Connections
===========
We recommend using `stunnel`_, `Tor`_ and `socat`_ along with
nymphemeral when downloading and sending messages. If you are a
`Whonix`_ user, you should go to :ref:`connections-whonix`. 

Stunnel
-------
*stunnel* adds *TLS* to your connections. You can install it with::

    sudo apt-get install stunnel4

To configure *stunnel*, you can use the ``.conf`` file we provide
with nymphemeral. Copy that file to the directory where *stunnel*
looks for config files (which is usually ``/etc/stunnel``)::

    sudo curl https://raw.githubusercontent.com/felipedau/nymphemeral/master/connections/stunnel.conf -o /etc/stunnel/stunnel.conf

Open ``/etc/default/stunnel4`` and enable *stunnel* automatic startup
by switching ``ENABLE`` to ``1``::

    # Change to one to enable stunnel automatic startup
    ENABLED=1

And start it with::

    sudo service stunnel4 start

You should get the following message::

    Starting SSL tunnels: [Started: /etc/stunnel/stunnel.conf] stunnel.

Tunelling
'''''''''
From the last sections of the ``.conf`` file::

    [nntps-client]
    client = yes
    accept = 127.0.0.1:119
    connect = 127.0.0.1:10063

    [ssmtp-client]
    protocol = smtp
    client = yes
    accept = 127.0.0.1:2525
    connect = 127.0.0.1:2526

Note that:

- The NNTP client is used to download messages. Whenever it accesses
  port ``119``, *stunnel* will connect it to port ``10063``, adding
  *TLS*.

- The SMTP client is used to send messages. Whenever it accesses port
  ``2525``, *stunnel* will connect it to port ``2526``, adding *TLS*.

Tor
---
*Tor* is a low-latency communication system used to hide your
traffic. If you wish to have the latest stable version you should use
`this option`_. If that is not the case, simply install it with::

    sudo apt-get install tor

Socat
-----
*socat* manages the last part of the process, which will make the
connections from your machine to the servers via *Tor*. You can
install it with::

    sudo apt-get install socat

A script should be used to make the connection itself. Copy both
*socat* scripts we provide with nymphemeral::

    curl https://raw.githubusercontent.com/felipedau/nymphemeral/master/connections/socnews.sh -o ~/socnews.sh
    curl https://raw.githubusercontent.com/felipedau/nymphemeral/master/connections/socsmtp.sh -o ~/socsmtp.sh

And enable them to be executed::

    chmod +x ~/socnews.sh ~/socsmtp.sh

News Server
'''''''''''
From the ``socnews.sh`` file::

    socat TCP-Listen:10063,bind=localhost,fork SOCKS4A:localhost:news.mixmin.net:563,socksport=9050 > /dev/null 2>&1 &

Note that *socat* accepts connections through port ``10063`` (the one
that *stunnel* connects to) and then connects to the news server at
*mixmin.net* via *Tor* through port ``9050``.

Run it with::

    ~/socnews.sh

SMTP Server
'''''''''''
From the ``socsmtp.sh`` file::

    socat TCP-Listen:2526,bind=localhost,fork SOCKS4A:localhost:lnwxejysejqjlm3l.onion:2525,socksport=9050 > /dev/null 2>&1 &

Note that *socat* accepts connections through port ``2526`` (the one
that *stunnel* connects to) and then connects to the `Jeremy Bentham
Remailer`_ SMTP server at anemonee.mooo.com via *Tor* through port
``9050``.

Run it with::

    ~/socsmtp.sh

You could also use other SMTP servers, such as these ones::

    mail.mixmin.net
    mail.allpingers.net

.. note::

    You can use whatever NNTP/SMTP servers you would like. We chose to
    use those for convenience, but you are totally free to configure
    other ones or setup your own.

.. important::

    You do not need to start *stunnel* or *Tor* again, but the scripts
    have to be executed every time the system starts up or whenever
    you wish to use nymphemeral.

.. _`jeremy bentham remailer`: http://anemone.mooo.com/stats/
.. _`socat`: http://www.dest-unreach.org/socat
.. _`stunnel`: https://www.stunnel.org
.. _`this option`: https://www.torproject.org/docs/debian.html.en#ubuntu
.. _`tor`: https://www.torproject.org
.. _`whonix`: https://whonix.org
