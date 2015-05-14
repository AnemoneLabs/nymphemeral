================
Starting Session
================
.. figure:: login.png
   :scale: 70%
   :alt: Login Window
   :align: right

   Login Window

When you run the client, a login window will be displayed. Fill in
the ``Address`` and ``Passhphrase`` fields, choose the output method
that you would like to use and click ``Start Session``.

GPG Agent
---------
If it is enabled, the GPG Agent's dialogs will be displayed when you
need to sign/decrypt messages, prompting you for a passphrase. If you
decide not to enable it, nymphemeral's own dialogs will be used.

Output method
-------------
When **Mixmaster** is installed and configured, clicking the
``Send via Mixmaster`` radio button on the login screen will route
all messages to the nymserv through the Mixmaster network
automatically.

If you have **sendmail** configured and running on your machine, you
can also choose to send messages to the nymserv as regular email via
the ``Send via Email`` radio button automatically.

If you would rather send messages manually, select the
``Display Output in Message Window`` radio button and then copy the
encrypted message from the message window for transmission. If you
choose this option it is your responsibility to send the encrypted
message to the server. When this last method is being used, the
client assumes that the message will get to the server. Therefore,
when you finish the creation process, the nym information will be
written to disk right away as well as it will be deleted when you
confirm to delete the nym.

**Important:** Regardless the method that is being used, information
about the message that has just been created is displayed in the
first lines of the text box from the current tab.

Managing Servers
----------------
If the nymserver's public key is not found in the keyring, you will
be prompted to add it. You can also add, modify or delete these
public keys whenever you want by clicking on ``Manage Servers`` in
the login window.

.. figure:: key.png
   :scale: 55%
   :alt: Key Manager Window
   :align: left

   Key Manager Window

.. figure:: servers.png
   :scale: 80%
   :alt: Server Manager Window
   :align: right

   Server Manager Window
