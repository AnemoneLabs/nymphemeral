"""
aampy - a simple message downloader for a.a.m

Copyright (C) 2015 by Felipe Dau <dau.felipe@gmail.com> and
David R. Andersen <k0rx@RXcomm.net>

This program differs from the original version found at
https://github.com/rxcomm/aampy. It was modified to be ran
concurrently with a client. If you wish to run aampy as a script, you
should download the original version from the link above.

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
import calendar
import copy
import email
import nntplib
import socket
import string
import threading
import time

from dateutil import parser, tz

import hsub


class AAMpy(object):
    def __init__(self, directory, group, server, port, is_debugging=False):
        self._directory = directory
        self._group = group
        self._server = server
        self._port = port
        self._is_debugging = is_debugging

        self._event = None
        self._is_running = None
        self._server_found = None
        self._timestamp = None
        self._progress_ratio = None

    @property
    def event(self):
        return self._event

    @property
    def is_running(self):
        return self._is_running

    @property
    def server_found(self):
        return self._server_found

    @property
    def timestamp(self):
        return self._timestamp

    @property
    def progress_ratio(self):
        return self._progress_ratio

    def reset(self):
        self._event = threading.Event()
        self._is_running = None
        self._server_found = None
        self._timestamp = None
        self._progress_ratio = None

    def stop(self):
        self._is_running = False
        self._event.set()

    def retrieve_messages(self, hsubs):
        if self._is_debugging:
            print 'aampy is running'

        self._server_found = False
        self._timestamp = None
        self._progress_ratio = None
        self._is_running = True

        try:
            server = nntplib.NNTP(self._server, self._port)
        except socket.error:
            if self._is_debugging:
                print 'The news server cannot be found'
            self.stop()
            return
        else:
            self._server_found = True

        temp_hsubs = copy.deepcopy(hsubs)
        try:
            timestamp = float(temp_hsubs['time'])
        except KeyError:
            timestamp = time.time() - 3600.0
            if self._is_debugging:
                print 'Timestamp not found, aampy will download messages from last hour'
        else:
            del temp_hsubs['time']

        YYMMDD = time.strftime('%y%m%d', time.gmtime(timestamp))
        HHMMSS = time.strftime('%H%M%S', time.gmtime(timestamp))

        # download messages
        response, articles = server.newnews(self._group, YYMMDD, HHMMSS)
        total_messages = len(articles)
        messages_checked = 0
        self._progress_ratio = 0

        for msg_id in articles:
            if self._event.is_set():
                if self._is_debugging:
                    print 'aampy was interrupted'
                return
            try:
                resp, id, message_id, text = server.article(msg_id)
            except (nntplib.error_temp, nntplib.error_perm):
                # no such message (maybe it was deleted?)
                pass
            else:
                message = email.message_from_string(string.join(text, '\n'))
                for nick, passphrase in temp_hsubs.items():
                    for label, item in message.items():
                        if label == 'Subject':
                            match = hsub.check(passphrase, item)
                            # if match: write message to file
                            if match:
                                if self._is_debugging:
                                    print 'Found a message for nickname ' + nick
                                file_name = 'message_' + nick + '_' + message_id[1:6] + '.txt'
                                with open(self._directory + '/' + file_name, 'w') as f:
                                    f.write(message.as_string()+'\n')
                                    if self._is_debugging:
                                        print 'Encrypted message stored in ' + file_name
                date = parser.parse(message.get('Date'))
                if date:
                    self._timestamp = float(calendar.timegm(date.astimezone(tz.tzutc()).timetuple()))
                messages_checked += 1
                self._progress_ratio = float(messages_checked) / float(total_messages)

        if self._timestamp == timestamp:
            self._timestamp = None

        if self._is_debugging:
            print 'aampy is done'
        self.stop()
