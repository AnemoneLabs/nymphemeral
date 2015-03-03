`nymphemeral`_
==============

Features
--------
- Created to be used with the `new nymserv`_, a Zax-style nym server with
  forward secrecy
- Uses `python-gnupg`_ and `pyaxo`_ for encryption
- Uses `aampy`_ to retrieve messages from `alt.anonymous.messages`_
- Sends messages through `mixmaster`_, sendmail, or outputs the resulting
  ciphertexts to be sent manually
- Manages the nym servers public keys

Current Release
---------------
The current version of nymphemeral is 1.3.1, a prototype, released 2015-03-03.

Installation (on a Debian Wheezy/Ubuntu Trusty system)
------------------------------------------------------
**Main Dependencies:**

If you use `pip`_, install nymphemeral with::

    sudo pip install nymphemeral

The dependencies will be automatically downloaded and installed. **You can go
to the next section (other dependencies).**

If you do not use *pip*, first make sure that you have the following::

    sudo apt-get install python-dev python-tk

nymphemeral also uses `pyaxo`_, `python-dateutil`_ and `python-gnupg`_, and
the easiest way to install those is using `setuptools`_. After making sure you
have *setuptools*, from nymphemeral's source folder, install with::

    sudo python setup.py install

The dependencies will be installed automatically.

If you do not use *setuptools* as well, you will have to install each
dependency and sub-dependencies manually.

**Other Dependencies:**

nymphemeral will be ready for use after installation via either of the two
methods described above. However, you should install the following
dependencies to be able to use all of its features.

*mixmaster*

Follow the `mixmaster instructions`_ to get `mixmaster`_ running. **Make sure
you have** `OpenSSL`_ **1.0.1g or later.**
If your *mixmaster* configuration is located anywhere other than the default
``~/Mix`` directory, you should edit ``~/.config/nymphemeral/nymphemeral.cfg``
to point to your configuration.

*news server*

*aampy*'s default news server configured in ``nymphemeral.cfg`` is set to
``localhost``, port ``119``. This default is useful if you use `stunnel`_ to
encrypt the connection between ``localhost:119`` and your actual news server.
If you want to connect directly to the news server, you should edit
``nymphemeral.cfg`` and change the address and port of the news server
appropriately. Unfortunately, the **python 2.7 nntplib** module does not
support connections over SSL/TLS.

**Optional:** you can use `Tor`_ along with *aampy* and *mixmaster*. An
example `stunnel`_ configuration, useful for encrypting your news feed, is
located in ``/usr/share/nymphemeral/connections``. There is also sample
`socat`_ scripts for tunneling messages and news downloads via *Tor*.

Usage
-----

To run nymphemeral, type the following at the command line::

    nymphemeral

nymphemeral only works with the `new nymserv`_. Currently, `nym.now.im`_
is the only nym server running this code. The nymphemeral GUI is very
friendly and should be straightforward. When the client is run for the first
time, ``nymphemeral.cfg`` will be automatically created in the
``~/.config/nymphemeral`` directory and you can edit it per your liking. You
can also read the `client instructions`_ to better understand how it works.

**Tip:** If encryption is taking too long, your system probably does not have
enough entropy. Using tools such as `haveged`_ or `rng-tools`_ may solve this
issue.

Bug Tracker
-----------
Please report any suggestions, feature requests, bug reports, or annoyances
to the GitHub `issue tracker`_.

**Thanks to** `rxcomm`_ **for the new nymserv, nym.now.im, pyaxo, aampy and
for assisting on the development of this client. Thanks to** `crooks`_ **(Zax)
for the original nymserv software. Thanks to** `tych0`_ **for assisting on
fixes and improvements.**

.. _`aampy`: https://github.com/rxcomm/aampy
.. _`alt.anonymous.messages`: https://groups.google.com/forum/#!forum/alt.anonymous.messages
.. _`client instructions`: https://felipedau.github.io/nymphemeral/usage/usage.html
.. _`crooks`: https://github.com/crooks
.. _`haveged`: http://www.issihosts.com/haveged/
.. _`issue tracker`: https://github.com/felipedau/nymphemeral/issues
.. _`mixmaster instructions`: https://anemone.mooo.com/mixmaster.html
.. _`mixmaster`: http://www.zen19351.zen.co.uk/mixmaster302
.. _`new nymserv`: https://github.com/rxcomm/nymserv
.. _`nym.now.im`: http://nym.now.im/nymserver
.. _`nymphemeral`: https://felipedau.github.io/nymphemeral
.. _`openssl`: https://www.openssl.org
.. _`pip`: https://pypi.python.org/pypi/pip
.. _`pyaxo`: https://github.com/rxcomm/pyaxo
.. _`python-dateutil`: https://pypi.python.org/pypi/python-dateutil
.. _`python-gnupg`: https://pypi.python.org/pypi/python-gnupg
.. _`rng-tools`: https://www.gnu.org/software/hurd/user/tlecarrour/rng-tools.html
.. _`rxcomm`: https://github.com/rxcomm
.. _`setuptools`: https://pypi.python.org/pypi/setuptools
.. _`socat`: http://www.dest-unreach.org/socat
.. _`stunnel`: https://www.stunnel.org
.. _`tor`: https://www.torproject.org
.. _`tych0`: https://github.com/tych0
