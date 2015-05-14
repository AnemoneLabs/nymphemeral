===============
Files Structure
===============
After installing the client, run nymphemeral at the command line and
it will create the following files and directories inside the base
directory (``~/.config/nymphemeral``):

- ``*.gpg``: *GPG* keyring files

- ``nymphemeral.cfg``: Config file that stores preferences and paths
  used by the client. This file is not encrypted and does not have
  sensitive data

- hSub files that store the hSub passphrases of the nyms

  - ``encrypted_hsubs.txt``: File encrypted to every nym (with
    asymmetric encryption) by one that has access to it

  - ``hsubs.txt``: File used to store (temporarily) the hSub
    passphrases of new nyms that still do not have access to the
    encrypted one

- ``db``: Database directory that stores the conversation states of
  all the nyms. These databases are protected with symmetric
  encryption (using the passphrases the user provided when creating
  each nym)

- ``messages``: Directory that stores the read and unread messages

  - ``unread``: Directory that stores the messages downloaded from
    the news group, that are already encrypted with ephemeral
    encryption from the server

  - ``read``: Directory that stores the messages the user chose to
    save, that are encrypted with asymmetric encryption, where the
    nym encrypted to itself

Configuring nymphemeral
-----------------------
You can modify ``nymphemeral.cfg`` per your liking. We will not
describe the whole file, but only the options relevant to the user
that belong to the following sections:

[gpg]
'''''
Although this option can be modified through the GUI, you can toggle
``use_agent`` between ``True``/``False`` to use the GPG Agent when
signing/decrypting messages. (Default: ``True``)

[main]
''''''
Toggle ``debug_switch`` between ``True``/``False`` to log information
regarding operations performed by the client. (Default: ``False``)

[mixmaster]
'''''''''''
You can set ``base_folder`` to point to your *Mixmaster* installation.
(Default: ``~/Mix``).

[newsgroup]
'''''''''''
If you already have a news server running, replace ``group``,
``server`` and ``port`` with its information. Otherwise, visit
:ref:`newsserver` to find out how to create one using *socat*
and *stunnel*.

**Important:** Changes made to ``nymphemeral.cfg`` will only take
effect by restarting the client.
