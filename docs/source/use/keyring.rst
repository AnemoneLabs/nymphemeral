.. _keyring:

===========
GPG Keyring
===========
nymphemeral has its own GPG keyring within its base directory
and it does not access information from the user keyring. Therefore,
if you are going to use End-to-End Encryption, you have to manually
add the respective key to the keyring.

More information regarding End-to-End Encryption can be found in the
:ref:`composition` and :ref:`decryption` sections.

Adding Key
----------
Considering you will encrypt a message to a user whose public key is
in the ``pkey.asc`` file in the home directory. You can add it to
nymphemeral's keyring with::

    gpg --homedir ~/.config/nymphemeral --import ~/pkey.asc

Now you can type its UID or fingerprint when encrypting the message.

Similarly, you can also add private keys to the keyring if you expect
to receive messages encrypted to a specific key you have. Either the
GPG Agent or nymphemeral will automatically prompt you for a
passphrase and decrypt the message.

.. _sec-default-keys:

Default Keys
------------
nymphemeral's package includes the public keys of the `nym.now.im`_
server and the nymphemeral nym. By importing the former to the client
keyring you are able to create and use nyms on that server, and if you
need to contact us, the latter allows you to send end-to-end encrypted
messages to ``nymphemeral@nym.now.im``. In order to import them you
should click ``Import Default Keys`` in the ``Nym Servers`` window
(presented in :ref:`sec-managing-servers`).

The included keys can be found in the ``nymphemeral.keyring`` module
as ``.asc`` files and a `detached signature`_ of *nym.now.im's* public
key signed by the Jeremy Bentham Remailer Admin can be used to verify
the ``nym-now-im-server.asc`` file.

.. _`detached signature`: https://nym.now.im/nymserver/key.txt
.. _`nym.now.im`: https://nym.now.im/nymserver
