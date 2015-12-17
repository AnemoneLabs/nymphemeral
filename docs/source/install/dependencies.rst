.. _main-dependencies:

=================
Main Dependencies
=================
If you use `pip`_, install nymphemeral with::

    sudo pip install nymphemeral

The dependencies will be automatically downloaded and installed.
You can go to :ref:`other-dependencies`.

If you do not use *pip*, first make sure that you have the
following::

    sudo apt-get install python-dev python-tk

nymphemeral also uses `pyaxo`_, `python-dateutil`_ and
`python-gnupg`_, and the easiest way to install those is using
`setuptools`_. After making sure you have *setuptools*, from
nymphemeral's source folder, install with::

    sudo python setup.py install

The dependencies will be installed automatically.

If you do not use *setuptools* as well, you will have to install each
dependency and sub-dependencies manually.

Updating
--------
If you installed nymphemeral with *pip*, you can also use it for
updates::

    sudo pip install --upgrade nymphemeral

.. _other-dependencies:

Other Dependencies
------------------
nymphemeral will be ready for use after installation via either of
the two methods described in :ref:`main-dependencies`. However, you
should follow the instructions from :ref:`connections`, install
:ref:`mixmaster` and have a :ref:`newsserver` running to be able to
use all of its features.

.. _`pip`: https://pypi.python.org/pypi/pip
.. _`pyaxo`: https://github.com/rxcomm/pyaxo
.. _`python-dateutil`: https://pypi.python.org/pypi/python-dateutil
.. _`python-gnupg`: https://pypi.python.org/pypi/python-gnupg
.. _`setuptools`: https://pypi.python.org/pypi/setuptools
