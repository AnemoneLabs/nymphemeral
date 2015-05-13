================
Sending Messages
================
Sending a message is simple. Fill in the ``Target Email Address``,
``Subject`` and ``Message`` fields and click ``Send``.

.. figure:: send.png
   :scale: 50%
   :alt: Send Message Tab
   :align: left

   Send Message Tab

.. figure:: sent.png
   :scale: 50%
   :alt: Sent Message
   :align: right

   Sent Message

Optional Headers
----------------
In the ``Headers`` text box, other headers can be added to the
message in the format::

    HeaderA: InformationA
    HeaderB: InformationB

Example
'''''''
I know a server that allows me to post messages to *Usenet*. I
provide its email address in the ``Target Email Address`` and as I
wish to post to *alt.privacy.anon-server*, I type the following
header in the ``Headers`` text box::

    Newsgroups: alt.privacy.anon-server

The server will process the message and the post should arrive in
the news group.
