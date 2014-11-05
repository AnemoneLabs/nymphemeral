#!/usr/bin/env python

import email
import sys
import re

from dateutil import parser


class Message():
    def __init__(self, is_unread, string, identifier):
        self.is_unread = is_unread
        self.processed_message = email.message_from_string(string)
        self.identifier = identifier
        self.sender = None
        self.subject = None
        self.date = None
        self.content = None
        self.title = None
        self.retrieve_attributes()

    def retrieve_attributes(self):
        try:
            m = self.processed_message
            title = ''

            if 'date' in m:
                self.date = parser.parse(m.get('date'))
                title += str(self.date)[:16] + ' '

            if 'from' in m:
                sender = m.get('from')
                self.sender = re.search('[^( |<)]+@[^( |>)]+', sender).group(0)
                title += self.sender + ': '
            else:
                title = 'Unknown sender: '

            if 'subject' in m:
                self.subject = m.get('subject')
                title += self.subject
            else:
                title += '(no subject)'

            # content types we print
            mtypes = ('text/plain', 'text/html', 'message/rfc822')

            if m.is_multipart():
                content = ''
                for part in m.walk():
                    if part['Content-Transfer-Encoding'] == 'base64' and part.get_content_type() in mtypes:
                        content += part.get_payload(decode=True)
                    elif part.get_content_type() in mtypes:
                        content += part.as_string()
                    else:
                        pass
            else:
                if self.processed_message['Content-Transfer-Encoding'] == 'base64':
                    content = self.processed_message.get_payload(decode=True)
                else:
                    content = self.processed_message.get_payload()

            self.content = content

            if self.is_unread:
                title = 'Undecrypted message'
                if self.date:
                    title += ' - ' + str(self.date)
            self.title = title
        except:
            print 'Error while retrieving attributes: ', sys.exc_info()[0]
            raise