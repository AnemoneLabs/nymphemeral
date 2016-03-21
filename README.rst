nymphemeral
-----------
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

Quick Install
-------------
Make sure that you have the following::

    sudo apt-get install python-dev python-tk # If using Debian/Ubuntu
    sudo yum install python-devel tkinter # If using Fedora

If you use `pip`_ and `setuptools`_ (probably installed automatically
with *pip*), you can easily install nymphemeral with::

    sudo pip install nymphemeral

You should at least read `news server`_ to make sure you have one
running and configured so that your nyms can receive messages.

Updating
''''''''
If you installed nymphemeral with *pip*, you can also use it for
updates::

    sudo pip install --upgrade nymphemeral

Documentation
-------------
You can find `installation`_ and `usage`_ instructions (with
screenshots) on the `documentation`_, as well as nymphemeral's
`limitations`_.

Protocol Update
---------------
**nymphemeral 1.3.3** was updated to use **pyaxo 0.4** that follows
the latest (Oct 1, 2014) version of the protocol, which changed the
order of the ratcheting. For that reason, old conversations (created
with **nymphemeral < 1.3.3**) might not work properly after the
update. We suggest that users update nymphemeral and restart their
conversations by changing their nyms' **ephemeral keys**. The
`Configuring the Nym`_ section explains how that can be done.

Feedback and Contact
--------------------
Please use the `GitHub issue tracker`_ to leave suggestions, feature
requests, bug reports, complaints or any contribution to nymphemeral.
If you feel the need to talk about something else, send messages to
``nymphemeral@nym.now.im``. You can also use its `public key`_ for
end-to-end encryption.

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
.. _`configuring the nym`: http://nymphemeral.readthedocs.org/en/latest/use/configuration.html
.. _`crooks`: https://github.com/crooks
.. _`documentation`: http://nymphemeral.readthedocs.org/
.. _`github issue tracker`: https://github.com/felipedau/nymphemeral/issues
.. _`hulahoopwhonix`: https://github.com/HulaHoopWhonix
.. _`installation`: http://nymphemeral.readthedocs.org/en/latest/install/dependencies.html
.. _`limitations`: http://nymphemeral.readthedocs.org/en/latest/overview.html#limitations
.. _`mixmaster`: http://www.zen19351.zen.co.uk/mixmaster302
.. _`news server`: http://nymphemeral.readthedocs.org/en/latest/install/newsserver.html
.. _`new nymserv`: https://github.com/rxcomm/nymserv
.. _`pip`: https://pypi.python.org/pypi/pip
.. _`public key`: https://raw.githubusercontent.com/felipedau/nymphemeral/master/docs/source/nymphemeral-nym.asc
.. _`pyaxo`: https://github.com/rxcomm/pyaxo
.. _`python-gnupg`: https://pypi.python.org/pypi/python-gnupg
.. _`rxcomm`: https://github.com/rxcomm
.. _`setuptools`: https://pypi.python.org/pypi/setuptools
.. _`tych0`: https://github.com/tych0
.. _`usage`: http://nymphemeral.readthedocs.org/en/latest/use/login.html
.. _`zax-type`: https://github.com/crooks/nymserv
.. _`whonix`: https://whonix.org
