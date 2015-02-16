#!/usr/bin/env python
"""
nymphemeral - an ephemeral nymserver GUI client

Messages are retrieved from a.a.m using aampy.py and hsub.py
from https://github.com/rxcomm/aampy

Messages dates are parsed using python-dateutil 2.2 from
https://pypi.python.org/pypi/python-dateutil

Encryption is done using python-gnupg and pyaxo from
https://pypi.python.org/pypi/python-gnupg/
https://github.com/rxcomm/pyaxo

Copyright (C) 2014 by Felipe Dau <dau.felipe@gmail.com> and
David R. Andersen <k0rx@RXcomm.net>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

For more information, see https://github.com/felipedau/nymphemeral
"""

__author__ = 'Felipe Dau and David R. Andersen'
__license__ = 'GPL'
__version__ = '1.2.3'
__status__ = 'Prototype'

import Tkinter as tk
import ttk
import os
import tkMessageBox
import ConfigParser

from client import Client
from errors import *
from nym import Nym


cfg = ConfigParser.ConfigParser()

BASE_FILES_PATH = '/usr/share/nymphemeral'
USER_PATH = os.path.expanduser('~')
NYMPHEMERAL_PATH = USER_PATH + '/.config/nymphemeral'
CONFIG_FILE = NYMPHEMERAL_PATH + '/nymphemeral.cfg'
OUTPUT_METHOD = {
    'mixmaster': 1,
    'sendmail': 2,
    'manual': 3,
}


class Gui:
    def __init__(self):
        self.client = Client()

        self.window_login = LoginWindow(self)
        self.window_main = None

    def start_session(self, creating_nym):
        self.window_login.destroy()
        self.window_main = MainWindow(self, creating_nym)

    def end_session(self):
        self.client.end_session()
        self.window_main.destroy()
        self.window_login = LoginWindow(self)


class LoginWindow(tk.Tk, object):
    def __init__(self, gui):
        super(LoginWindow, self).__init__()

        self.gui = gui
        self.var_output_method = None

        self.title('nymphemeral')
        frame_login = tk.Frame(self)
        frame_login.grid(sticky='w', padx=15, pady=15)

        # title
        label_title = tk.Label(frame_login, text='nymphemeral', font=('Helvetica', 26))
        label_title.grid(sticky='n')

        # address
        label_address = tk.Label(frame_login, text='Address')
        label_address.grid(sticky='w', pady=(15, 0))
        entry_address_login = tk.Entry(frame_login)
        entry_address_login.grid(sticky='we')

        # passphrase
        label_passphrase = tk.Label(frame_login, text='Passphrase')
        label_passphrase.grid(sticky='w', pady=(10, 0))
        entry_passphrase_login = tk.Entry(frame_login, show='*')
        entry_passphrase_login.grid(sticky='we')

        # servers
        button_servers = tk.Button(frame_login, text='Manage Servers', command=lambda: ServersWindow(self.gui))
        button_servers.grid(pady=(5, 0))

        # output radio buttons
        frame_radio = tk.LabelFrame(frame_login, text='Output Method')
        frame_radio.grid(pady=(10, 0), ipadx=5, ipady=5, sticky='we')
        self.var_output_method = tk.IntVar()
        radio_mix = tk.Radiobutton(frame_radio, text='Send via Mixmaster', variable=self.var_output_method,
                                   value=OUTPUT_METHOD['mixmaster'])
        radio_mix.grid(pady=(5, 0), sticky='w')
        chain = self.gui.client.chain
        if not chain:
            radio_mix.config(state=tk.DISABLED)
            chain = 'Error while manipulating mix.cfg'
        label_chain = tk.Label(frame_radio, text=chain)
        label_chain.grid(sticky='w', padx=(25, 0))
        radio_email = tk.Radiobutton(frame_radio, text='Send via Email', variable=self.var_output_method,
                                     value=OUTPUT_METHOD['sendmail'])
        radio_email.grid(sticky='w')
        radio_text = tk.Radiobutton(frame_radio, text='Display Output in Message Window',
                                    variable=self.var_output_method,
                                    value=OUTPUT_METHOD['manual'])
        radio_text.grid(sticky='w')
        self.var_output_method.set(OUTPUT_METHOD[self.gui.client.output_method])

        # start button
        button_start = tk.Button(frame_login, text='Start Session',
                                 command=lambda: self.start_session(entry_address_login.get(),
                                                                    entry_passphrase_login.get()))
        button_start.grid(pady=(15, 0))
        self.bind('<Return>', lambda event: self.start_session(entry_address_login.get(),
                                                               entry_passphrase_login.get()))

        entry_address_login.focus_set()

    def start_session(self, address, passphrase, creating_nym=False):
        try:
            if not len(passphrase):
                raise InvalidPassphraseError
            nym = Nym(address, passphrase)
            self.gui.client.start_session(nym, creating_nym)
        except (InvalidEmailAddressError, InvalidPassphraseError, FingerprintNotFoundError,
                IncorrectPassphraseError) as e:
            tkMessageBox.showerror(e.title, e.message)
        except NymservNotFoundError as e:
            if tkMessageBox.askyesno(e.title, e.message + '\nWould you like to import it?'):
                KeyWindow(self.gui)
        except NymNotFoundError as e:
            if tkMessageBox.askyesno(e.title, e.message + '\nWould you like to create it?'):
                self.start_session(address, passphrase, True)
        else:
            self.gui.start_session(creating_nym)


class ServersWindow(tk.Tk, object):
    def __init__(self, gui):
        super(ServersWindow, self).__init__()

        self.gui = gui

        self.title('Nym Servers')
        frame_servers = tk.Frame(self)
        frame_servers.grid(sticky='w', padx=15, pady=15)

        # servers list box
        frame_list = tk.LabelFrame(frame_servers, text='Nym Servers')
        frame_list.grid(sticky='we')
        self.list_servers = tk.Listbox(frame_list, height=11, width=40)
        self.list_servers.grid(row=0, column=0, sticky='we')
        scrollbar_list = tk.Scrollbar(frame_list, command=self.list_servers.yview)
        scrollbar_list.grid(row=0, column=1, sticky='nsew')
        self.list_servers['yscrollcommand'] = scrollbar_list.set
        self.list_servers.bind('<<ListboxSelect>>', self.toggle_servers_interface)

        buttons_row = frame_servers.grid_size()[1] + 1

        # new button
        button_new_servers = tk.Button(frame_servers, text='New', command=lambda: KeyWindow(self.gui, self))
        button_new_servers.grid(row=buttons_row, sticky='w', pady=(10, 0))

        # modify button
        self.button_modify_servers = tk.Button(frame_servers, text='Modify',
                                               command=lambda: KeyWindow(self.gui, self,
                                                                               self.list_servers.get(
                                                                                   self.list_servers.curselection())),
                                               state=tk.DISABLED)
        self.button_modify_servers.grid(row=buttons_row, pady=(10, 0))

        # delete button
        self.button_delete_servers = tk.Button(frame_servers, text='Delete',
                                               command=lambda: self.delete_key(self.list_servers.get(
                                                   self.list_servers.curselection())),
                                               state=tk.DISABLED)
        self.button_delete_servers.grid(row=buttons_row, sticky='e', pady=(10, 0))

        self.update_servers_list()

    def toggle_servers_interface(self, event=None):
        if event:
            self.button_modify_servers.config(state=tk.NORMAL)
            self.button_delete_servers.config(state=tk.NORMAL)
        else:
            self.button_modify_servers.config(state=tk.DISABLED)
            self.button_delete_servers.config(state=tk.DISABLED)

    def update_servers_list(self):
        self.list_servers.delete(0, tk.END)
        for s in self.gui.client.retrieve_servers().keys():
            self.list_servers.insert(tk.END, s)
        self.toggle_servers_interface()

    def delete_key(self, server):
        if tkMessageBox.askyesno('Confirm', 'Are you sure you want to delete ' + server + "'s key?"):
            self.gui.client.delete_key(server)
            self.update_servers_list()


class KeyWindow(tk.Tk, object):
    def __init__(self, gui, parent=None, server=None):
        super(KeyWindow, self).__init__()

        self.gui = gui
        self.parent = parent

        self.title('Public Key Manager')

        frame_key = tk.Frame(self)
        frame_key.grid(sticky='w', padx=15, pady=15)

        # key text box
        key = ''
        if server:
            frame_list = tk.LabelFrame(frame_key, text=server + "'s Public Key")
            key = gui.client.gpg.export_keys(gui.client.retrieve_servers()[server])
        else:
            frame_list = tk.LabelFrame(frame_key, text='New Server Public Key')
        frame_list.grid(sticky='we')
        text_key = tk.Text(frame_list, height=22, width=66)
        text_key.grid(row=0, column=0, sticky='we')
        scrollbar_text = tk.Scrollbar(frame_list, command=text_key.yview)
        scrollbar_text.grid(row=0, column=1, sticky='nsew')
        text_key['yscrollcommand'] = scrollbar_text.set
        text_key.insert(tk.INSERT, key)

        # save button
        button_save_key = tk.Button(frame_key, text='Save',
                                    command=lambda: self.save_key(text_key.get(1.0, tk.END), server))
        button_save_key.grid(pady=(10, 0))

        text_key.mark_set(tk.INSERT, 1.0)
        text_key.focus_set()

    def save_key(self, key, server):
        self.gui.client.save_key(key, server)
        if self.parent:
            self.parent.update_servers_list()
        self.destroy()


class MainWindow(tk.Tk, object):
    def __init__(self, gui, creating_nym=False):
        super(MainWindow, self).__init__()

        self.gui = gui
        self.tabs = []

        # root window
        self.title('nymphemeral')

        # frame inside root window
        frame_tab = tk.Frame(self)
        frame_tab.pack()

        # tabs
        self.notebook = ttk.Notebook(frame_tab)
        self.notebook.pack()

        self.tab_inbox = tk.Frame(self.notebook)
        self.tabs.append(self.tab_inbox)
        self.notebook.add(self.tab_inbox, text='Inbox')

        self.tab_send = tk.Frame(self.notebook)
        self.tabs.append(self.tab_send)
        self.notebook.add(self.tab_send, text='Send Message')

        self.tab_configure = tk.Frame(self.notebook)
        self.tabs.append(self.tab_configure)
        self.notebook.add(self.tab_configure, text='Configure Nym')

        self.tab_unread = tk.Frame(self.notebook)
        self.tabs.append(self.tab_unread)
        self.notebook.add(self.tab_unread, text='Unread Counter')

        if creating_nym:
            self.tab_create = tk.Frame(self.notebook)
            self.tabs.append(self.tab_create)
            self.notebook.add(self.tab_create, text='Create Nym')
            self.set_creation_interface(True)

        self.notebook.pack(fill=tk.BOTH, expand=True)

        # footer
        frame_footer = tk.Frame(frame_tab)
        frame_footer.pack(fill=tk.X, expand=True, padx=5, pady=5)

        frame_left = tk.Frame(frame_footer)
        frame_left.pack(side=tk.LEFT)
        frame_address = tk.Frame(frame_left)
        frame_address.pack(fill=tk.X, expand=True)
        label_address = tk.Label(frame_address, text=self.gui.client.nym.address)
        label_address.pack(side=tk.LEFT)
        if self.gui.client.output_method is 'mixmaster':
            frame_chain = tk.Frame(frame_left)
            frame_chain.pack(fill=tk.X, expand=True)
            label_chain = tk.Label(frame_chain, text=self.gui.client.chain)
            label_chain.pack(side=tk.LEFT)
        button_change_nym = tk.Button(frame_footer, text='Change Nym', command=self.gui.end_session)
        button_change_nym.pack(side=tk.RIGHT)

        # move window to the center
        self.update_idletasks()
        window_w, window_h = self.winfo_width(), self.winfo_height()
        screen_w, screen_h = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry('%dx%d+%d+%d' % (window_w, window_h, (screen_w - window_w) / 2, (screen_h - window_h) / 2))

    def set_tab_state(self, tab, enabled):
        if enabled:
            state = tk.NORMAL
        else:
            state = tk.DISABLED
        self.notebook.tab(tab, state=state)

    def set_all_tabs_state(self, enabled, exceptions=[]):
        for tab in self.tabs:
            if tab not in exceptions:
                self.set_tab_state(tab, enabled)

    def set_creation_interface(self, creating):
        if creating:
            self.set_all_tabs_state(False, [self.tab_create])
        else:
            self.set_all_tabs_state(True)


if __name__ == '__main__':
    Gui().window_login.mainloop()