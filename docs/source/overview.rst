========
Overview
========
nymphemeral is a tool made for users searching for secure and
anonymous communication on the internet.

It is a GUI client that relies on a pseudonym remailer that
communicates to its users by posting messages to a shared mailbox,
a `Zax-type`_ nym server. Both the server and the client apply an
ephemeral encryption layer on their messages based on the `Axolotl
Ratchet protocol`_, providing forward and future secrecy to the
conversation.

Features
--------
- Manages pseudonym actions: creation, configuration and deletion,
  as well as message dispatch and retrieval

- Communicates with the `new nymserv`_, a *Zax-type* nym server with
  forward and future secrecy

- Uses `python-gnupg`_ and `pyaxo`_ for encryption

- Uses `aampy`_ to retrieve messages from `alt.anonymous.messages`_

- Sends messages through `Mixmaster`_, *sendmail*, or outputs the
  resulting ciphertexts to be sent manually

- Supports End-to-End Encryption

Current Release
---------------
The current version of nymphemeral is 1.4.2, a beta, released
2016-03-21.

Limitations
-----------

Regular Zax-type
''''''''''''''''
nymphemeral does not support the regular `Zax-type`_ nym server. It
only supports the `new nymserv`_, adding or expecting an ephemeral
encryption layer in its messages.

Mixmaster
'''''''''
Although it is supported (and the use is encouraged), nymphemeral is
not a *Mixmaster* GUI. It does enable the users to send their
messages to the nym server automatically via *Mixmaster*, but it
cannot be used to send regular email. nymphemeral is a **nym client**
and the only way to exchange messages is to send every message to the
nym server, to be processed and then remailed to the recipient.
*Mixmaster* is just one of the output methods.

.. important::

    **nymphemeral 1.3.3** was updated to use **pyaxo 0.4** that
    follows the latest (Oct 1, 2014) version of the protocol, which
    changed the order of the ratcheting. For that reason, old
    conversations (created with **nymphemeral < 1.3.3**) might not
    work properly after the update. We suggest that users update
    nymphemeral and restart their conversations by changing their
    nyms' **ephemeral keys**. The :ref:`sec-configuration` section
    explains how that can be done.

.. _`aampy`: https://github.com/rxcomm/aampy
.. _`alt.anonymous.messages`: https://groups.google.com/forum/#!forum/alt.anonymous.messages
.. _`axolotl ratchet protocol`: https://github.com/trevp/axolotl/wiki
.. _`mixmaster`: http://www.zen19351.zen.co.uk/mixmaster302
.. _`new nymserv`: https://github.com/rxcomm/nymserv
.. _`pyaxo`: https://github.com/rxcomm/pyaxo
.. _`python-gnupg`: https://pypi.python.org/pypi/python-gnupg
.. _`zax-type`: https://github.com/crooks/nymserv
