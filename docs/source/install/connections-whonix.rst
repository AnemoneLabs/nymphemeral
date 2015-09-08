.. _connections-whonix:

Connections (Whonix)
====================
The main :ref:`connections` section guides the user on how to use
`stunnel`_, `Tor`_ and `socat`_ along with nymphemeral on
Debian/Ubuntu. However if you are using `Whonix`_,  your `connections
are already made through Tor`_ and following those same instructions
would not only be unecessary, but would also create a `Tor over Tor
scenario`_, which is highly discouraged.

The good news is that these instructions are much simpler than the
default ones, because *Whonix* already comes with some things
set up for you.

Stunnel
-------
*stunnel* adds *TLS* to your connections. You can install it with::

    sudo apt-get install stunnel4

To configure *stunnel*, you can use the ``.conf`` file we provide
with nymphemeral. Copy that file to the directory where *stunnel*
looks for config files (which is usually ``/etc/stunnel``)::

    sudo curl https://raw.githubusercontent.com/felipedau/nymphemeral/master/connections/stunnel-whonix.conf -o /etc/stunnel/stunnel.conf

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
    connect = news.mixmin.net:563

    [ssmtp-client]
    protocol = smtp
    client = yes
    accept = 127.0.0.1:25
    connect = 2.2.2.2:25
    
Note that:

- The NNTP client is used to download messages. Whenever it accesses
  port ``119``, *stunnel* will connect it to the NNTP server on
  ``mixmin.net``, adding *TLS*.
  
- The SMTP client is used to send messages. Whenever it accesses port
  ``25``, *stunnel* will connect it to the SMTP server at ``2.2.2.2``,
  adding *TLS*. According to `Whonix's documentation`_, there are two
  addresses mapped to SMTP servers running as hidden services::

    mapaddress 1.1.1.1 k54ids7luh523dbi.onion
    mapaddress 2.2.2.2 gbhpq7eihle4btsn.onion

.. note::

    You can use whatever NNTP/SMTP servers you would like. We chose to
    use those for convenience, but you are totally free to configure
    other ones or setup your own.

You can go to :ref:`mixmaster-whonix`.

.. _`connections are already made through Tor`: https://www.whonix.org/wiki/About
.. _`socat`: http://www.dest-unreach.org/socat
.. _`stunnel`: https://www.stunnel.org
.. _`tor`: https://www.torproject.org
.. _`tor over tor scenario`: https://www.whonix.org/wiki/DoNot#Prevent_Tor_over_Tor_scenarios.
.. _`whonix`: https://whonix.org
.. _`whonix's documentation`: https://www.whonix.org/wiki/Dev/Mixmaster#Installing
