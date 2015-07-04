========
Overview
========
nymphemeral is a tool made for users searching for secure and
anonymous communication on the internet.

It is a GUI client that relies on a pseudonymous remailer that
communicates to its users by posting messages to a shared mailbox,
a **Zax-type** nym server. Both the server and the client apply an
ephemeral encryption layer on their messages based on the `Axolotl
Ratchet protocol`_, providing forward and future secrecy to the
conversation.

Features
--------
- Communicates with the `new nymserv`_, a *Zax-type* nym server with
  forward secrecy

- Uses `python-gnupg`_ and `pyaxo`_ for encryption

- Uses `aampy`_ to retrieve messages from `alt.anonymous.messages`_

- Sends messages through `Mixmaster`_, *sendmail*, or outputs the
  resulting ciphertexts to be sent manually

- Supports End-to-End Encryption

Current Release
---------------
The current version of nymphemeral is 1.3.2, a beta, released
2015-05-13.

Protocol Update
---------------
**nymphemeral 1.3.3** was updated to use **pyaxo 0.4** that follows
the latest (Oct 1, 2014) version of the protocol, which changed the
order of the ratcheting. For that reason, old conversations (created
with **nymphemeral < 1.3.3**) might not work properly after the
update. We suggest that users update nymphemeral and restart their
conversations by changing their nyms' **ephemeral keys** under the
``Configure Nym`` tab.

.. _`aampy`: https://github.com/rxcomm/aampy
.. _`alt.anonymous.messages`: https://groups.google.com/forum/#!forum/alt.anonymous.messages
.. _`axolotl ratchet protocol`: https://github.com/trevp/axolotl/wiki
.. _`mixmaster`: http://www.zen19351.zen.co.uk/mixmaster302
.. _`new nymserv`: https://github.com/rxcomm/nymserv
.. _`pyaxo`: https://github.com/rxcomm/pyaxo
.. _`python-gnupg`: https://pypi.python.org/pypi/python-gnupg
