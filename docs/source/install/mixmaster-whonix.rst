.. _mixmaster-whonix:

==================
Mixmaster (Whonix)
==================
Although we highly recommend following the instructions on
:ref:`mixmaster` to compile the large-key version of `Mixmaster`_, you
can use the one that comes installed with `Whonix`_, which is a bit
outdated.

You should know that compiling *Mixmaster* (i.e., following
:ref:`mixmaster`) would make the whole installation at ``~/Mix``.
However, the one that comes with *Whonix* (installed from Debian)
uses different locations. There are only two important ones you
should know: the user files are at ``~/.Mix`` and the binary at
``/usr/bin/mixmaster``. nymphemeral automatically searches for
*Mixmaster* files at those locations and you do not need to configure
anything (as explained on :ref:`cfg_mix`).

Getting New Remailer Stats
--------------------------
Before you can use *Mixmaster*, you need to update the stats. We are
going to use the pinger from the `Jeremy Bentham Remailer`_, but the
process should be similar to other pingers you wish to use.

An easy way to do this **securely** is with *curl*. First, create a
file called ``update.sh`` in your ``~/Mix`` directory, with the
following contents::

    #!/bin/bash
    rm pubring.asc pubring.mix mlist.txt rlist.txt
    curl http://lnwxejysejqjlm3l.onion/stats/mlist.txt -o mlist.txt
    curl http://lnwxejysejqjlm3l.onion/stats/rlist.txt -o rlist.txt
    curl http://lnwxejysejqjlm3l.onion/stats/pubring.mix -o pubring.mix
    curl http://lnwxejysejqjlm3l.onion/stats/pgp-all.asc -o pubring.asc

Change the script to executable mode::

    chmod +x update.sh

As there is no need to use a certificate for an onion service, you can
securely update your remailer stats by simply::

    ./update.sh

You should update the remailer stats *at least once a day* when using
*Mixmaster*.

Config File
-----------
*Mixmaster* just needs to be configured through the ``~/.Mix/mix.cfg``
file. A very simple config file could be written as follows::

    CHAIN *,*,*,*,*
    SMTPRELAY localhost

Chain (Optional)
''''''''''''''''
The ``CHAIN`` is the path that your messages will take before being
delivered. In the configuration above, the messages are going to pass
by five mixes, and finally get to the actual target. You can use any
sequence and number of mixes in the chain, passing their names or
simply ``*`` (which means that it could be any mix), separated by
commas.

.. note::

    Adding more mixes to the chain will probably increase the latency
    to deliver your messages. That is actually not a bad thing, but
    you should decide how long you are willing to wait to exchange
    messages.

SMTP Server
'''''''''''
If you followed :ref:`connections-whonix`, you remember that we will
use ``127.0.0.1:25`` to reach an SMTP server. Using the option
``SMTPRELAY`` will tell *Mixmaster* to use that specific connection.

.. note::

    nymphemeral should be ready to tunnel via Tor messages sent using
    Mixmaster!

You can go to :ref:`newsserver`.

.. _`mixmaster`: http://www.zen19351.zen.co.uk/mixmaster303
.. _`whonix`: https://whonix.org
