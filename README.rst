nymphemeral
-----------
nymphemeral is a tool made for users searching for secure and
anonymous communication on the internet.

It is a GUI client that relies on a pseudonymous remailer that
communicates to its users by posting messages to a shared mailbox,
a `Zax-type`_ nym server. Both the server and the client apply an
ephemeral encryption layer on their messages based on the `Axolotl
Ratchet protocol`_, providing forward and future secrecy to the
conversation.

Features
--------
- Manages pseudonymous actions: creation, configuration and
  deletion, as well as message dispatch and retrieval

- Communicates with the `new nymserv`_, a *Zax-type* nym server with
  forward secrecy

- Uses `python-gnupg`_ and `pyaxo`_ for encryption

- Uses `aampy`_ to retrieve messages from `alt.anonymous.messages`_

- Sends messages through `Mixmaster`_, *sendmail*, or outputs the
  resulting ciphertexts to be sent manually

- Supports End-to-End Encryption

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

Current Release
---------------
The current version of nymphemeral is 1.3.4, a beta, released
2015-07-22.

Protocol Update
---------------
**nymphemeral 1.3.3** was updated to use **pyaxo 0.4** that follows
the latest (Oct 1, 2014) version of the protocol, which changed the
order of the ratcheting. For that reason, old conversations (created
with **nymphemeral < 1.3.3**) might not work properly after the
update. We suggest that users update nymphemeral and restart their
conversations by changing their nyms' **ephemeral keys** under the
``Configure Nym`` tab.

Quick Install
-------------
If you use `pip`_, you can easily install nymphemeral with::

    sudo pip install nymphemeral

You should at least read `news server`_ to make sure you have one
running and configured so that your nyms can receive messages.

Documentation
-------------
You can find `installation`_ and `usage`_ instructions (with
screenshots) on the `documentation`_.

Feedback
--------
Please report any suggestions, feature requests, bug reports, or
annoyances to the `GitHub issue tracker`_.

Acknowledgements
----------------
- Thanks to `rxcomm`_ for the new nymserv, nym.now.im, pyaxo, aampy
  and for assisting on the development of this client

- Thanks to `crooks`_ (Zax) for the original nymserv software

- Thanks to `tych0`_ for assisting on fixes and improvements

- Thanks to `HulaHoopWhonix`_ (from the `Whonix`_ team) for testing
  and providing awesome feedback, such as bug reports, feature
  requests and suggestions

.. _`aampy`: https://github.com/rxcomm/aampy
.. _`alt.anonymous.messages`: https://groups.google.com/forum/#!forum/alt.anonymous.messages
.. _`axolotl ratchet protocol`: https://github.com/trevp/axolotl/wiki
.. _`crooks`: https://github.com/crooks
.. _`documentation`: http://nymphemeral.readthedocs.org/
.. _`github issue tracker`: https://github.com/felipedau/nymphemeral/issues
.. _`hulahoopwhonix`: https://github.com/HulaHoopWhonix
.. _`installation`: http://nymphemeral.readthedocs.org/en/latest/install/dependencies.html
.. _`mixmaster`: http://www.zen19351.zen.co.uk/mixmaster302
.. _`news server`: http://nymphemeral.readthedocs.org/en/latest/install/newsserver.html
.. _`new nymserv`: https://github.com/rxcomm/nymserv
.. _`pip`: https://pypi.python.org/pypi/pip
.. _`pyaxo`: https://github.com/rxcomm/pyaxo
.. _`python-gnupg`: https://pypi.python.org/pypi/python-gnupg
.. _`rxcomm`: https://github.com/rxcomm
.. _`tych0`: https://github.com/tych0
.. _`usage`: http://nymphemeral.readthedocs.org/en/latest/use/login.html
.. _`zax-type`: https://github.com/crooks/nymserv
.. _`whonix`: https://whonix.org
