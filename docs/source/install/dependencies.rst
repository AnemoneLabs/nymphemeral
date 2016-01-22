.. _main-dependencies:

=================
Main Dependencies
=================
Make sure that you have the following::

    sudo apt-get install python-dev python-tk # If using Debian/Ubuntu
    sudo yum install python-devel tkinter # If using Fedora

If you use `pip`_, you can easily install nymphemeral with::

    sudo pip install nymphemeral

The other dependencies used by nymphemeral such as `pyaxo`_,
`python-dateutil`_ and `python-gnupg`_ will be automatically
downloaded and installed. You can go to :ref:`other-dependencies`.

If you do not use *pip*, the easiest way to install those
dependencies is using `setuptools`_. After making sure you have
*setuptools*, install with::

    git clone https://github.com/felipedau/nymphemeral
    cd nymphemeral/
    sudo python setup.py install

nymphemeral and its dependencies should be installed.

If you do not use *setuptools* as well, you will have to install each
dependency and sub-dependencies manually.

.. _other-dependencies:

Other Dependencies
------------------
nymphemeral will be ready for use after installation via either of
the two methods described in :ref:`main-dependencies`. However, you
should follow the instructions from :ref:`connections`, install
:ref:`mixmaster` and have a :ref:`newsserver` running to be able to
use all of its features.

Updating
--------
If you installed nymphemeral with *pip*, you can also use it for
updates::

    sudo pip install --upgrade nymphemeral

.. _`pip`: https://pypi.python.org/pypi/pip
.. _`pyaxo`: https://github.com/rxcomm/pyaxo
.. _`python-dateutil`: https://pypi.python.org/pypi/python-dateutil
.. _`python-gnupg`: https://pypi.python.org/pypi/python-gnupg
.. _`setuptools`: https://pypi.python.org/pypi/setuptools
