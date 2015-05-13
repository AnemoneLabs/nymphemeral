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
