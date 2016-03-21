=========
Changelog
=========

nymphemeral 1.4.2, released 2016-03-21
======================================

- Make the login interface more intuitive and close #21

- Minor interface enhancements

- Require `setuptools` only

- Include default keys and close #29

- Organize imports and close #37

nymphemeral 1.4.1, released 2016-02-13
======================================

- Add nymphemeral's own method to check a nym's passphrase

- Fix issue when retrieving nyms due to a change to python-gnupg

- Enable auto-generation of ephemeral and hSub keys

- Add method to retrieve a specific nym

- Add expiration attributes to the ``Nym`` class and display the
  expiration date on the GUI

nymphemeral 1.4, released 2015-12-19
====================================

- Make a proper entry point to launch the GUI

- Close #24 by using versioneer for version management

nymphemeral 1.3.6, released 2015-12-17
======================================

- Fix issue #26 to format the key info of nyms without expiration

- Fix issue #30 to not crash nymphemeral when a mix chain is not found

- Add an ``Updating`` section to the docs

- Do not call the package manager to install dependencies

nymphemeral 1.3.5, released 2015-09-09
======================================

- Improve the logger level

- Add more information to the installation sections

- Define which attributes and methods of Client are private

- Improve the code (add constants, simplify methods, remove
  redundancy)

- Fix bug to save new databases in the ``db`` directory

nymphemeral 1.3.4, released 2015-07-22
======================================

- Improve recognition of the Mixmaster installation

- Clarify nymphemeral's features and limitations

- Add instructions for Whonix

nymphemeral 1.3.3, released 2015-07-18
======================================

- Use pyaxo 0.4

- Use Python's logging module

- Slightly improve aampy's performance

- Improve parsing of the config file

- Improve and add more input validation

- Bug fixes and code improvements

nymphemeral 1.3.2, released 2015-05-13
======================================

- Add End-to-End encryption

  - Encrypt

  - Throw key IDs

  - Sign

  - Support GPG agent

- Redesign aampy

nymphemeral 1.3.1, released 2015-03-03
======================================

- Create client module

- Modify the GUI to be a layer between the user and the client

nymphemeral 1.2.3, released 2015-02-14
======================================

- Remove dependency links processing from `pip install`

nymphemeral 1.2.2.1, released 2014-11-14
========================================

- Remember the output method being used

nymphemeral 1.2.1, release 2014-11-10
=====================================

- Append date to the title of the messages in the 'inbox'

- Encrypt hSub passphrases

- Support headers added by the user at the top of the message being
  composed

- Add the 'In-Reply-To' header to the reply
