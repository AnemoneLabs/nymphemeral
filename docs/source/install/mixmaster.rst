.. _mixmaster:

=========
Mixmaster
=========
This article describes how to compile the new large-key version of
*Mixmaster* on a *Debian Wheezy* system. Most of its content was
taken from `this post`_ by the `Jeremy Bentham Remailer`_ Admin. The
instructions should be helpful for building *Mixmaster* on other
flavors of linux as well. See :ref:`ubuntu-loader` for a change if
using *Ubuntu*.

Preliminaries
-------------
First, you need to install the packages required by *Mixmaster* and
*OpenSSL*::

    sudo apt-get install build-essential libpcre3-dev wget \
    zlib1g-dev libncurses5-dev curl perl bc dc bison libbison-dev

Build OpenSSL
-------------
Then you need to compile a version of *OpenSSL* that contains the
*IDEA* cipher. Grab the most recent version (make sure it is version
1.0.1g or later!) from the `OpenSSL download page`_.

Extract the tarball (substituting your version for 1.0.1g)::

    tar xvf openssl-1.0.1g.tar.gz

Build the distribution::

    cd openssl-1.0.1g
    ./config
    make
    make test
    sudo make install

Note that this installs *OpenSSL* into ``/usr/local/ssl``. Symlink
the new *OpenSSL* installation into your normal lib and include
directories so that the *Mixmaster* install script can find them.
Note that the ``sudo mv`` instructions below will only work if you
have previous copies of the files installed. If you get an error
along the lines of ``mv: cannot stat libssl.a`` or similar, just
ignore it - you did not have a file there to move::

    cd /usr/lib
    sudo mv libssl.a libssl.a.old
    sudo ln -s /usr/local/ssl/lib/libssl.a libssl.a
    sudo mv libcrypto.a libcrypto.a.old
    sudo ln -s /usr/local/ssl/lib/libcrypto.a libcrypto.a
    cd /usr/include
    sudo mv openssl openssl.old
    sudo ln -s /usr/local/ssl/include/openssl openssl


Build Mixmaster
---------------

Download `Mixmaster 3.0.3`_.

Be sure to verify the SHA256 hash of the downloaded file. You can do
this by executing the command::

    sha256sum mixmaster-3.0.3b.tar.gz

The output should match the following hex number::

    4cd6121e49cddba9b0771d453fa7b6cf824bee920af36206d1414388a47708de

Extract the *Mixmaster* tarball::

    tar xvf mixmaster-3.0.3b.tar.gz

Run the ``Install`` script::

    cd mixmaster-3.0.3b
    ./Install

Answer the questions posed by the script:

- You can just press enter when it prompts for the installation
  directory. It will be installed at ``~/Mix``

- Do not worry about the *OpenSSL* version questions - 1.0.1g+ is so
  new the script does not know about it - select the default **YES**

- Your new version of *OpenSSL* **does** have AES encryption, so
  answer **YES** to that question as well

- As we are going to only use *Mixmaster* as a client (with
  nymphemeral), answer **NO** to the question about running a
  remailer

*Mixmaster* should be installed successfully.

.. _ubuntu-loader:

Ubuntu Loader Changes
'''''''''''''''''''''
If you are using *Ubuntu* and see the following compile error::

    gcc mix.o rem.o rem1.o rem2.o chain.o chain1.o chain2.o nym.o pgp.o pgpdb.o pgpdata.o pgpget.o pgpcreat.o pool.o mail.o rfc822.o mime.o keymgt.o compress.o stats.o crypto.o random.o util.o buffers.o maildir.o parsedate.tab.o rndseed.o menu.o menusend.o menunym.o menuutil.o menustats.o main.o /usr/local/ssl/lib/libcrypto.a  -lz -L/usr/lib/x86_64-linux-gnu/ -lpcre -L/usr/lib/x86_64-linux-gnu/  -lncurses -L/usr/lib/x86_64-linux-gnu/ -o mixmaster
    /usr/bin/ld: /usr/local/ssl/lib/libcrypto.a(dso_dlfcn.o): undefined reference to symbol 'dlclose@@GLIBC_2.2.5'
    /lib/x86_64-linux-gnu/libdl.so.2: error adding symbols: DSO missing from command line
    collect2: error: ld returned 1 exit status
    make: *** [mixmaster] Error 1
    Error: The compilation failed. Please consult the documentation (section `Installation problems').

you should make the following changes to the ``Install`` script, due
to modifications *Ubuntu* has made to the loader.

On line ``402`` of the ``Install`` script, change::

    LDFLAGS=

to::

    LDFLAGS="-ldl"

Getting New Remailer Stats
--------------------------
Before you can use *Mixmaster*, you need to update the stats. We are
going to use the pinger from the `Jeremy Bentham Remailer`_, but the
process should be similar to other pingers you wish to use.

An easy way to do this **securely** is with *curl*. First, create a
file called ``update.sh`` in your ``~/Mix`` directory, with the
following contents::

    #!/bin/bash
    export SSL_CERT_DIR=$HOME/Mix/certs
    rm pubring.asc pubring.mix mlist.txt rlist.txt
    curl --cacert ./certs/anemone.pem https://anemone.mooo.com/stats/mlist.txt -o mlist.txt
    curl --cacert ./certs/anemone.pem https://anemone.mooo.com/stats/rlist.txt -o rlist.txt
    curl --cacert ./certs/anemone.pem https://anemone.mooo.com/stats/pubring.mix -o pubring.mix
    curl --cacert ./certs/anemone.pem https://anemone.mooo.com/stats/pgp-all.asc -o pubring.asc

Change the script to executable mode::

    chmod +x update.sh

Next, create the ``~/Mix/certs`` directory and add
*anemone.mooo.com's* certificate::

    mkdir ~/Mix/certs
    cd ~/Mix/certs
    wget http://anemone.mooo.com/anemone.pem

Now that you have downloaded the certificate file, you can securely
update your remailer stats by simply::

    cd ~/Mix
    ./update.sh

You should update the remailer stats *at least once a day* when using
*Mixmaster*.

.. _tor-socat-stunnel:

Tor, Socat and Stunnel
----------------------
As we mentioned, we recommend using `Tor`_ along with *Mixmaster*.
You can install it with::

    sudo apt-get install tor

or you can use `another option`_ if you wish to have the most recent
version.

For the tunneling, you should also download `socat`_ and `stunnel`_::

    sudo apt-get install socat stunnel4

To configure *stunnel*, you can use the ``.conf`` file we provide
with nymphemeral. Copy that file to the directory where *stunnel*
looks for .conf files (which is usually ``/etc/stunnel``)::

    sudo cp /usr/share/nymphemeral/connections/stunnel.conf /etc/stunnel

Open ``/etc/default/stunnel4`` and enable *stunnel* automatic startup
by switching ``ENABLE`` to ``1``::

    # Change to one to enable stunnel automatic startup
    ENABLED=1

And start it with::

    sudo service stunnel4 start

You should get the following message::

    Starting SSL tunnels: [Started: /etc/stunnel/stunnel.conf] stunnel.

Now you need to start the tunneling itself. Copy ``socsmtp.sh`` as
well::

    cp /usr/share/nymphemeral/connections/socsmtp.sh ~

Enable it to be executed::

    chmod +x ~/socsmtp.sh

And finally, run it::

    cd
    ./socsmtp.sh

**nymphemeral should be ready to tunnel via Tor messages sent
using Mixmaster!**

**Note:** You do not need to start *stunnel* again, but this script
has to be executed every time the system starts up.

.. _`another option`: https://www.torproject.org/docs/debian.html.en#ubuntu
.. _`jeremy bentham remailer`: http://anemone.mooo.com/stats/
.. _`mixmaster 3.0.3`: http://www.zen19351.zen.co.uk/mixmaster303
.. _`openssl download page`: https://www.openssl.org/source/
.. _`socat`: http://www.dest-unreach.org/socat
.. _`stunnel`: https://www.stunnel.org
.. _`this post`: http://anemone.mooo.com/mixmaster.html
.. _`tor`: https://www.torproject.org
