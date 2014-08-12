#!/usr/bin/env python
"""
aampy - a simple message downloader for a.a.m

Copyright (C) 2014 by Felipe Dau <dau.felipe@gmail.com> and
David R. Andersen <k0rx@RXcomm.net>

This program differs from the original version found on
https://github.com/rxcomm/aampy. It was modified to be used along
with nymphemeral. As it is run concurrently with the GUI client, it
expects parameters such as an event for synchronization and a config
object. Therefore, it should only be used by the client. If you wish
to run aampy manually, download the original version from the link
above.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

For more information, https://github.com/felipedau/nymphemeral
"""

import nntplib
import time
import email
import string
import sys

import hsub


def aam(event, cfg):
    # load configs
    is_debugging = cfg.getboolean('main', 'debug_switch')
    directory_unread_messages = cfg.get('main', 'unread_folder')
    file_hsub = cfg.get('main', 'hsub_file')
    group = cfg.get('newsgroup', 'group')
    newsserver = cfg.get('newsgroup', 'server')
    newsport = int(cfg.get('newsgroup', 'port'))

    if is_debugging:
        print 'aampy is running'

    try:
        hsubpassphrases = readDict(file_hsub)
        try:
            timeStamp = float(hsubpassphrases['time'])
            del hsubpassphrases['time']
        except KeyError:
            timeStamp = time.time() - 3600.0
            if is_debugging:
                print 'Reading messages from last hour (no timestamp in' + file_hsub.split('/')[-1] + ')'
        curTime = time.time()
        YYMMDD = time.strftime('%y%m%d', time.gmtime(timeStamp))
        HHMMSS = time.strftime('%H%M%S', time.gmtime(timeStamp))
    except IOError:
        print file_hsub.split('/')[-1] + ' file not found - exiting!'
        sys.exit(1)

    # connect to server
    server = nntplib.NNTP(newsserver, newsport)
    server.newnews(group, YYMMDD, HHMMSS, '.newnews')

    with open('.newnews', 'r') as f:
        ids = f.read().splitlines()

        for msg_id in ids:
            if event.is_set():
                if is_debugging:
                    print 'aampy was interrupted'
                return
            try:
                resp, id, message_id, text = server.article(msg_id)
            except (nntplib.error_temp, nntplib.error_perm):
                pass  # no such message (maybe it was deleted?)
            text = string.join(text, "\n")

            message = email.message_from_string(text)
            match = False

            for nick, passphrase in hsubpassphrases.items():
                for label, item in message.items():
                    if label == 'Subject':
                        match = hsub.check(passphrase, item)
                        #if match: write message to file
                        if match:
                            if is_debugging:
                                print 'Found a message for nickname ' + nick
                            fileName = 'message_' + nick + '_' + message_id[1:6] + '.txt'
                            with open(directory_unread_messages + '/' + fileName, "w") as f:
                                f.write(message.as_string()+'\n')
                                if is_debugging:
                                    print 'Encrypted message stored in ' + fileName

    hsubpassphrases['time'] = curTime
    writeDict(file_hsub, hsubpassphrases)
    if is_debugging:
        print 'aampy is done'
    event.set()


def readDict(file):
    with open(file, 'r') as f:
        d = dict(line.strip().split(' ', 1) for line in f)
    return d


def writeDict(file, d):
    with open(file, 'w') as f:
        for key, item in d.iteritems():
            f.write(key + ' ' + str(item) + '\n')

if __name__ == '__main__':
    aam()