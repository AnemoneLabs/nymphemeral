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
The value of ``logger_level`` can be modified to control what
nymphemeral logs on the console. These values are the same ones used
by Python's logging module. You can choose from:

+----------+
| debug    |
+----------+
| info     |
+----------+
| warning  |
+----------+
| error    |
+----------+
| critical |
+----------+

**Example:** ``debug`` is the most sensitive level. When it is set,
every message will be logged from ``debug`` to ``critical``.
(Default: ``warning``)

.. _cfg_mix:

[mixmaster]
'''''''''''
This section defines the paths nymphemeral searches for *Mixmaster's*
binary and config file. Values defined on this section will be checked
before the default paths *Mixmaster* usually uses for both compiled
(as instructed on :ref:`mixmaster`) and installed (with the package
manager) versions:

+--------+-------------------+------------------+
| Option | Compiled          | Installed        |
+========+===================+==================+
| binary | `~/Mix/mixmaster` | `mixmaster`      |
+--------+-------------------+------------------+
| cfg    | `~/Mix/mix.cfg`   | `~/.Mix/mix.cfg` |
+--------+-------------------+------------------+

If your *Mixmaster* installation is different from these values, you
must change the ``binary`` and ``cfg`` options accordingly.
nymphemeral calls ``--version`` on the binary and checks for the
existence of the config file. Only after checking that *Mixmaster* is
some derivative of **Mixmaster 3** and the config file is found, it
assumes it is installed and working. Finally it searches for the
*mix chain* to be displayed on the GUI, but will not prevent
*Mixmaster* to be used if it is not found.

[newsgroup]
'''''''''''
If you already have a news server running, replace ``group``,
``server`` and ``port`` with its information. Otherwise, visit
:ref:`newsserver` to find out how to create one using *socat*
and *stunnel*.

.. important::

    Changes made to ``nymphemeral.cfg`` will only take effect by
    restarting the client.
