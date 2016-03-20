.. _main-dependencies:

=================
Main Dependencies
=================
Make sure that you have the following::

    sudo apt-get install python-dev python-tk # If using Debian/Ubuntu
    sudo yum install python-devel tkinter # If using Fedora

If you use `pip`_ and `setuptools`_ (probably installed automatically
with *pip*), you can easily install nymphemeral with::

    sudo pip install nymphemeral

The other dependencies used by nymphemeral such as `pyaxo`_,
`python-dateutil`_ and `python-gnupg`_ will be automatically
downloaded and installed. You can go to :ref:`other-dependencies`.

If you do not use *pip*, you at least have to install *setuptools*. It
provides a few features needed by nymphemeral and will also
automatically install the dependencies mentioned above. After making
sure you have *setuptools*, install with::

    git clone https://github.com/felipedau/nymphemeral
    cd nymphemeral/
    sudo python setup.py install

nymphemeral and its dependencies should be installed.

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
