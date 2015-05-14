nymphemeral
-----------
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

.. _`aampy`: https://github.com/rxcomm/aampy
.. _`alt.anonymous.messages`: https://groups.google.com/forum/#!forum/alt.anonymous.messages
.. _`axolotl ratchet protocol`: https://github.com/trevp/axolotl/wiki
.. _`crooks`: https://github.com/crooks
.. _`documentation`: http://nymphemeral.readthedocs.org/
.. _`github issue tracker`: https://github.com/felipedau/nymphemeral/issues
.. _`installation`: http://nymphemeral.readthedocs.org/en/latest/install/dependencies.html
.. _`mixmaster`: http://www.zen19351.zen.co.uk/mixmaster302
.. _`new nymserv`: https://github.com/rxcomm/nymserv
.. _`pyaxo`: https://github.com/rxcomm/pyaxo
.. _`python-gnupg`: https://pypi.python.org/pypi/python-gnupg
.. _`rxcomm`: https://github.com/rxcomm
.. _`tych0`: https://github.com/tych0
.. _`usage`: http://nymphemeral.readthedocs.org/en/latest/use/login.html
