# [nymphemeral] 
# an ephemeral nymserver GUI client

## Features
- Uses [python-gnupg] and [pyaxo] for encryption
- Uses [aampy] to retrieve messages from [alt.anonymous.messages]
- Sends messages through [mixmaster], sendmail and outputs the resulting cyphertexts
to be sent manually (if it is the case)
- Manages the nymservers public keys

## Current Release
The current version of [nymphemeral] is 1.0.4, a prototype, released 2014-08-12.

## Installation (on a Debian Wheezy system)
- Install Tkinter with `sudo apt-get install python-tk`
- Due to the various date formats used by the servers, [python-dateutil] is being used to
parse them. Install it as well
- Follow the instructions on [pyaxo]'s GitHub page to install it. **Make sure to install
[python-gnupg]**
- If you do not have a newsgroup server running, install [socat] and [stunnel] to set one
up so you will be able to retrieve messages using [aampy]. Examples of stunnel's .conf
file and socat's scripts are located in the `connections` folder
- Follow the [mixmaster instructions] to get [mixmaster] running. **Make sure you have
[OpenSSL] 1.0.1g or later**
- **Optional:** you can use [Tor] along with [aampy] and [mixmaster]
- From the `nymphemeral` folder, run `./nymphemeral.py`

## Usage
The GUI is very friendly and should be straightforward. When the client is ran for the
first time, `nymphemeral.cfg` will be automatically created and you can edit it per your
liking. You can also read the [client instructions] to better understand how it works.

**Important:** If you would like to use a nym that already exists (created without using
the client), you will have to add its keys to the keyring, its database to the `db`
folder and also add its hSub key to the `hsubpass.txt` file.

## Bug Tracker
Please report any suggestions, feature requests, bug reports, or annoyances
to the GitHub [issue tracker].

# Thank you!

[nymphemeral]: https://github.com/felipedau/nymphemeral
[mixmaster]: http://www.zen19351.zen.co.uk/mixmaster302
[aampy]: https://github.com/rxcomm/aampy
[alt.anonymous.messages]: https://groups.google.com/forum/#!forum/alt.anonymous.messages
[python-gnupg]: https://pypi.python.org/pypi/python-gnupg
[pyaxo]: https://github.com/rxcomm/pyaxo
[python-dateutil]: https://pypi.python.org/pypi/python-dateutil
[socat]: http://www.dest-unreach.org/socat
[stunnel]: https://www.stunnel.org
[mixmaster instructions]: https://anemone.mooo.com/mixmaster.html
[openssl]: https://www.openssl.org
[client instructions]: https://felipedau.github.io/nymphemeral/usage/usage.html
[tor]: https://www.torproject.org
[issue tracker]: https://github.com/felipedau/nymphemeral/issues
