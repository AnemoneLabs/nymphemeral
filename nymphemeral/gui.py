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
__version__ = '1.3.1'
__status__ = 'Prototype'

import Tkinter as tk
import ttk
import os
import tkMessageBox

from client import Client, OUTPUT_METHOD
import errors
from nym import Nym


def write_on_text(text, content, clear=True):
    if clear:
        text.delete(1.0, tk.END)
    for c in content:
        text.insert(tk.INSERT, c)


class Gui:
    def __init__(self):
        self.client = Client()

        self.window_login = LoginWindow(self, self.client)
        self.window_main = None

    def start_session(self, creating_nym):
        self.window_login.destroy()
        self.window_login = None
        self.window_main = MainWindow(self, self.client, creating_nym)

    def end_session(self):
        if not self.client.aampy_is_done:
            self.window_main.stop_retrieving_messages()
        self.client.end_session()
        self.window_main.destroy()
        self.window_main = None
        self.window_login = LoginWindow(self, self.client)


class LoginWindow(tk.Tk, object):
    def __init__(self, gui, client):
        super(LoginWindow, self).__init__()

        self.gui = gui
        self.client = client
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
        button_servers = tk.Button(frame_login, text='Manage Servers', command=lambda: ServersWindow(self.gui,
                                                                                                     self.client))
        button_servers.grid(pady=(5, 0))

        # output radio buttons
        frame_radio = tk.LabelFrame(frame_login, text='Output Method')
        frame_radio.grid(pady=(10, 0), ipadx=5, ipady=5, sticky='we')
        self.var_output_method = tk.IntVar()
        radio_mix = tk.Radiobutton(frame_radio, text='Send via Mixmaster', variable=self.var_output_method,
                                   value=OUTPUT_METHOD['mixmaster'])
        radio_mix.grid(pady=(5, 0), sticky='w')
        chain = self.client.chain
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
        self.var_output_method.set(OUTPUT_METHOD[self.client.output_method])

        # start button
        button_start = tk.Button(frame_login, text='Start Session',
                                 command=lambda: self.start_session(entry_address_login.get(),
                                                                    entry_passphrase_login.get()))
        button_start.grid(pady=(15, 0))
        self.bind('<Return>', lambda event: self.start_session(entry_address_login.get(),
                                                               entry_passphrase_login.get()))

        entry_address_login.focus_set()

    def get_output_method(self):
        for key, i in OUTPUT_METHOD.iteritems():
            if i == self.var_output_method.get():
                return key

    def start_session(self, address, passphrase, creating_nym=False):
        method = self.get_output_method()
        try:
            nym = Nym(address, passphrase)
            if not len(passphrase):
                raise errors.InvalidPassphraseError()
            self.client.start_session(nym, method, creating_nym)
        except (errors.InvalidEmailAddressError, errors.InvalidPassphraseError, errors.FingerprintNotFoundError,
                errors.IncorrectPassphraseError) as e:
            tkMessageBox.showerror(e.title, e.message)
        except errors.NymservNotFoundError as e:
            if tkMessageBox.askyesno(e.title, e.message + '\nWould you like to import it?'):
                KeyWindow(self.gui, self.client)
        except errors.NymNotFoundError as e:
            if tkMessageBox.askyesno(e.title, e.message + '\nWould you like to create it?'):
                self.start_session(address, passphrase, True)
        else:
            self.gui.start_session(creating_nym)


class ServersWindow(tk.Tk, object):
    def __init__(self, gui, client):
        super(ServersWindow, self).__init__()

        self.gui = gui
        self.client = client

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
        button_new_servers = tk.Button(frame_servers, text='New', command=lambda: KeyWindow(self.gui, self.client,
                                                                                            self))
        button_new_servers.grid(row=buttons_row, sticky='w', pady=(10, 0))

        # modify button
        self.button_modify_servers = tk.Button(frame_servers, text='Modify',
                                               command=lambda: KeyWindow(self.gui, self.client, self,
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
        for s in self.client.retrieve_servers().keys():
            self.list_servers.insert(tk.END, s)
        self.toggle_servers_interface()

    def delete_key(self, server):
        if tkMessageBox.askyesno('Confirm', 'Are you sure you want to delete ' + server + "'s key?"):
            self.client.delete_key(server)
            self.update_servers_list()


class KeyWindow(tk.Tk, object):
    def __init__(self, gui, client, parent=None, server=None):
        super(KeyWindow, self).__init__()

        self.gui = gui
        self.client = client
        self.parent = parent

        self.title('Public Key Manager')

        frame_key = tk.Frame(self)
        frame_key.grid(sticky='w', padx=15, pady=15)

        # key text box
        key = ''
        if server:
            frame_list = tk.LabelFrame(frame_key, text=server + "'s Public Key")
            key = self.client.gpg.export_keys(self.client.retrieve_servers()[server])
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
        self.client.save_key(key, server)
        if self.parent:
            self.parent.update_servers_list()
        self.destroy()


class MainWindow(tk.Tk, object):
    def __init__(self, gui, client, creating_nym=False):
        super(MainWindow, self).__init__()

        self.gui = gui
        self.client = client
        self.id_after = None
        self.tabs = []
        self.tab_inbox = None
        self.tab_send = None
        self.tab_configure = None
        self.tab_unread = None
        self.tab_create = None

        # root window
        self.title('nymphemeral')

        # frame inside root window
        frame_tab = tk.Frame(self)
        frame_tab.pack()

        # tabs
        self.notebook = ttk.Notebook(frame_tab)
        self.notebook.pack()

        self.tab_send = SendTab(self.gui, self.client, self.notebook)
        self.tabs.append(self.tab_send)

        self.tab_configure = ConfigTab(self.gui, self.client, self.notebook)
        self.tabs.append(self.tab_configure)

        self.tab_unread = UnreadCounterTab(self.gui, self.client, self.notebook)
        self.tabs.append(self.tab_unread)

        self.tab_inbox = InboxTab(self.gui, self.client, self.tab_send, self.tab_unread, self.notebook)
        self.tabs.append(self.tab_inbox)

        self.notebook.add(self.tab_inbox, text='Inbox')
        self.notebook.add(self.tab_send, text='Send Message')
        self.notebook.add(self.tab_configure, text='Configure Nym')
        self.notebook.add(self.tab_unread, text='Unread Counter')

        if creating_nym:
            self.tab_create = CreationTab(self.gui, self.client, self.notebook)
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
        label_address = tk.Label(frame_address, text=self.client.nym.address)
        label_address.pack(side=tk.LEFT)
        if self.client.output_method == 'mixmaster':
            frame_chain = tk.Frame(frame_left)
            frame_chain.pack(fill=tk.X, expand=True)
            label_chain = tk.Label(frame_chain, text=self.client.chain)
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

    def stop_retrieving_messages(self):
        if self.id_after:
            self.after_cancel(self.id_after)
            self.id_after = None
        self.tab_inbox.stop_retrieving_messages()

    def select_tab(self, tab):
        self.notebook.select(tab)


class CreationTab(tk.Frame, object):
    def __init__(self, gui, client, parent):
        super(CreationTab, self).__init__(parent)

        self.gui = gui
        self.client = client

        frame_tab = tk.Frame(self)
        frame_tab.grid(sticky='nswe', padx=15, pady=15)

        # ephemeral
        label_ephemeral = tk.Label(frame_tab, text='Ephemeral Key')
        label_ephemeral.grid(sticky='w')
        self.entry_ephemeral_create = tk.Entry(frame_tab)
        self.entry_ephemeral_create.grid(sticky='we')

        # hSub
        label_hsub = tk.Label(frame_tab, text='hSub Passphrase')
        label_hsub.grid(sticky=tk.W, pady=(10, 0))
        self.entry_hsub_create = tk.Entry(frame_tab)
        self.entry_hsub_create.grid(sticky='we')

        # name
        label_name = tk.Label(frame_tab, text='Name')
        label_name.grid(sticky=tk.W, pady=(10, 0))
        self.entry_name_create = tk.Entry(frame_tab)
        self.entry_name_create.grid(sticky='we')

        # duration
        label_duration = tk.Label(frame_tab, text='Duration')
        label_duration.grid(sticky=tk.W, pady=(10, 0))
        self.entry_duration_create = tk.Entry(frame_tab)
        self.entry_duration_create.grid(sticky='we')

        # create button
        self.button_create = tk.Button(frame_tab, text='Create Nym',
                                       command=lambda: self.create(self.entry_ephemeral_create.get().strip(),
                                                                   self.entry_hsub_create.get().strip(),
                                                                   self.entry_name_create.get().strip(),
                                                                   self.entry_duration_create.get().strip()))
        self.button_create.grid(pady=(10, 0))

        # message box
        frame_text = tk.LabelFrame(frame_tab, text='Nym Creation Headers and Configuration')
        frame_text.grid(sticky='we', pady=10)
        self.text_create = tk.Text(frame_text, height=25)
        self.text_create.grid(row=0, column=0)
        scrollbar = tk.Scrollbar(frame_text, command=self.text_create.yview)
        scrollbar.grid(row=0, column=1, sticky='ns')
        self.text_create['yscrollcommand'] = scrollbar.set
        self.text_create.insert(tk.INSERT,
                                'Key generation may take a long time after you click the "Create Nym" button.'
                                '\nBe prepared to wait...')

    def set_interface(self, enabled):
        if enabled:
            state = tk.NORMAL
        else:
            state = tk.DISABLED
        self.entry_ephemeral_create.config(state=state)
        self.entry_hsub_create.config(state=state)
        self.entry_name_create.config(state=state)
        self.entry_duration_create.config(state=state)
        self.button_create.config(state=state)

    def create(self, ephemeral, hsub, name, duration):
        try:
            if not len(ephemeral):
                raise errors.InvalidEphemeralKeyError()
            if not len(hsub):
                raise errors.InvalidHsubError()
        except (errors.InvalidHsubError, errors.InvalidEphemeralKeyError) as e:
            tkMessageBox.showerror(e.title, e.message)
        else:
            success, info, ciphertext = self.client.send_create(ephemeral, hsub, name, duration)
            write_on_text(self.text_create, [info, ciphertext])
            if success:
                self.set_interface(False)
                self.gui.window_main.set_creation_interface(False)


class InboxTab(tk.Frame, object):
    def __init__(self, gui, client, tab_send, tab_unread, parent):
        super(InboxTab, self).__init__(parent)

        self.gui = gui
        self.client = client
        self.tab_send = tab_send
        self.tab_unread = tab_unread
        self.messages = None
        self.current_message_index = None

        frame_tab = tk.Frame(self)
        frame_tab.grid(sticky='nswe', padx=15, pady=15)

        frame_retrieve = tk.Frame(frame_tab)
        frame_retrieve.grid(sticky='w', pady=(0, 10))

        # retrieve button
        self.button_aampy_inbox = tk.Button(frame_retrieve, width=14, text='Retrieve Messages',
                                            command=self.start_retrieving_messages)
        self.button_aampy_inbox.grid(row=0, sticky='w')

        # progress bar
        self.progress_bar_inbox = ttk.Progressbar(frame_retrieve, mode='indeterminate', length=427)

        # messages list box
        frame_list = tk.LabelFrame(frame_tab, text='Messages')
        frame_list.grid(sticky='we')
        self.list_messages_inbox = tk.Listbox(frame_list, height=11, width=70)
        self.list_messages_inbox.grid(row=0, column=0, sticky='we')
        scrollbar_list = tk.Scrollbar(frame_list, command=self.list_messages_inbox.yview)
        scrollbar_list.grid(row=0, column=1, sticky='nsew')
        self.list_messages_inbox['yscrollcommand'] = scrollbar_list.set
        self.list_messages_inbox.bind('<<ListboxSelect>>', self.select_message)

        # content list box
        frame_text = tk.LabelFrame(frame_tab, text='Content')
        frame_text.grid(pady=10, sticky='we')
        self.text_content_inbox = tk.Text(frame_text, height=22)
        self.text_content_inbox.grid(row=0, column=0, sticky='we')
        scrollbar_text = tk.Scrollbar(frame_text, command=self.text_content_inbox.yview)
        scrollbar_text.grid(row=0, column=1, sticky='nsew')
        self.text_content_inbox['yscrollcommand'] = scrollbar_text.set

        buttons_row = frame_tab.grid_size()[1] + 1

        # save/delete button
        self.button_save_del_inbox = tk.Button(frame_tab, text='Save to Disk', command=self.save_and_update_interface)
        self.button_save_del_inbox.grid(row=buttons_row, sticky='w', pady=(10, 0))

        # reply button
        self.button_reply_inbox = tk.Button(frame_tab, text='Reply Message', command=self.reply_message)
        self.button_reply_inbox.grid(row=buttons_row, sticky='e', pady=(10, 0))

        # notification label
        self.label_save_del_inbox = tk.Label(frame_tab)
        self.label_save_del_inbox.grid(row=buttons_row, pady=(10, 0))

        self.load_messages()

    def update_messages_list(self):
        self.toggle_interface(False)
        self.list_messages_inbox.delete(0, tk.END)
        for m in self.messages:
            self.list_messages_inbox.insert(tk.END, m.title)
        try:
            self.tab_unread.update_unread_counter()
        except AttributeError:
            pass

    def load_messages(self):
        self.messages = self.client.retrieve_messages_from_disk()
        self.current_message_index = None
        self.update_messages_list()

    def start_retrieving_messages(self):
        self.client.start_aampy()
        self.wait_for_retrieval()
        self.toggle_interface(True)

    def stop_retrieving_messages(self):
        self.client.stop_aampy()
        self.toggle_interface(False)

    def wait_for_retrieval(self):
        if self.client.aampy_is_done:
            self.gui.window_main.id_after = None
            if self.client.queue_aampy.get()['server_found']:
                self.load_messages()
            else:
                self.toggle_interface(False)
                tkMessageBox.showerror('Socket Error', 'The news server cannot be found!')
        else:
            self.gui.window_main.id_after = self.gui.window_main.after(1000, lambda: self.wait_for_retrieval())

    def toggle_interface(self, retrieving_messages):
        self.button_save_del_inbox.config(state=tk.DISABLED)
        self.button_reply_inbox.config(state=tk.DISABLED)
        if retrieving_messages:
            self.list_messages_inbox.config(state=tk.DISABLED)
            self.text_content_inbox.config(state=tk.DISABLED)
            self.progress_bar_inbox.grid(row=0, column=1, sticky='nswe', padx=(15, 0))
            self.progress_bar_inbox.start(25)
            self.button_aampy_inbox.config(text='Stop', command=self.stop_retrieving_messages)
        else:
            self.list_messages_inbox.config(state=tk.NORMAL)
            self.text_content_inbox.config(state=tk.NORMAL)
            self.progress_bar_inbox.stop()
            self.progress_bar_inbox.grid_forget()
            self.button_aampy_inbox.config(text='Retrieve Messages', command=self.start_retrieving_messages)

    def select_message(self, event):
        if len(self.messages) and self.client.aampy_is_done:
            index = int(event.widget.curselection()[0])
            selected_message = self.messages[index]
            self.current_message_index = index

            if selected_message.is_unread:
                self.button_save_del_inbox.config(state=tk.DISABLED)
                self.button_reply_inbox.config(state=tk.DISABLED)

                try:
                    self.messages[index] = self.client.decrypt_ephemeral_message(selected_message)
                except errors.UndecipherableMessageError as e:
                    tkMessageBox.showerror(e.title, e.message)
                    self.messages.pop(index)
                    self.current_message_index = None
                    self.update_messages_list()
                else:
                    write_on_text(self.text_content_inbox, [self.messages[index].content])
                    self.update_messages_list()
                    self.toggle_save_del_button(True)
                    self.button_save_del_inbox.config(state=tk.NORMAL)
                    self.button_reply_inbox.config(state=tk.NORMAL)
            else:
                if os.path.exists(selected_message.identifier):
                    self.toggle_save_del_button(False)
                else:
                    self.toggle_save_del_button(True)
                write_on_text(self.text_content_inbox, [selected_message.content])
                self.button_save_del_inbox.config(state=tk.NORMAL)
                self.button_reply_inbox.config(state=tk.NORMAL)

    def toggle_save_del_button(self, toggle_save):
        if toggle_save:
            self.button_save_del_inbox.config(text='Save to Disk', command=self.save_and_update_interface)
        else:
            self.button_save_del_inbox.config(text='Delete from Disk', command=self.delete_and_update_interface)

    def save_and_update_interface(self):
        if self.client.save_message_to_disk(self.messages[self.current_message_index]):
            self.toggle_save_del_button(False)
            self.show_label_save_del('Message saved')

    def delete_and_update_interface(self):
        if self.client.delete_message_from_disk(self.messages[self.current_message_index]):
            self.toggle_save_del_button(True)
            self.show_label_save_del('Message deleted')

    def show_label_save_del(self, text):
        self.label_save_del_inbox.config(text=text)
        self.gui.window_main.after(3000, lambda: self.label_save_del_inbox.config(text=''))

    def reply_message(self):
        self.tab_send.compose_message(self.messages[self.current_message_index])


class SendTab(tk.Frame, object):
    def __init__(self, gui, client, parent):
        super(SendTab, self).__init__(parent)

        self.gui = gui
        self.client = client

        frame_tab = tk.Frame(self)
        frame_tab.grid(sticky='nswe', padx=15, pady=15)

        # target
        label_target = tk.Label(frame_tab, text='Target Email Address')
        label_target.grid(sticky=tk.W)
        self.entry_target_send = tk.Entry(frame_tab)
        self.entry_target_send.grid(sticky='we')

        # subject
        label_subject = tk.Label(frame_tab, text='Subject')
        label_subject.grid(sticky=tk.W, pady=(10, 0))
        self.entry_subject_send = tk.Entry(frame_tab)
        self.entry_subject_send.grid(sticky='we')

        # message box
        frame_text = tk.LabelFrame(frame_tab, text='Message')
        frame_text.grid(pady=10)
        self.text_send = tk.Text(frame_text, height=32)
        self.text_send.grid(row=0, column=0)
        scrollbar = tk.Scrollbar(frame_text, command=self.text_send.yview)
        scrollbar.grid(row=0, column=1, sticky='ns')
        self.text_send['yscrollcommand'] = scrollbar.set

        # send button
        button_send = tk.Button(frame_tab, text='Send',
                                command=lambda: self.send_message(self.entry_target_send.get().strip(),
                                                                  self.entry_subject_send.get().strip(),
                                                                  self.text_send.get(1.0, tk.END).strip()))
        button_send.grid()

    def compose_message(self, msg):
        self.entry_target_send.delete(0, tk.END)
        if msg.sender:
            self.entry_target_send.insert(0, msg.sender.lower())
        self.entry_subject_send.delete(0, tk.END)
        if msg.subject:
            self.entry_subject_send.insert(0, 'Re: ' + msg.subject)
        content = '\n\n'
        for line in msg.content.splitlines():
            content += '> ' + line + '\n'
        cursor_position = 1.0
        message_id = msg.processed_message.get('Message-ID')
        if message_id:
            content = 'In-Reply-To: ' + message_id + '\n\n' + content
            cursor_position = 3.0
        write_on_text(self.text_send, [content])
        self.text_send.mark_set(tk.INSERT, cursor_position)
        self.gui.window_main.select_tab(self)
        self.text_send.focus_set()

    def send_message(self, target_address, subject, content):
        success, info, ciphertext = self.client.send_message(target_address, subject, content)
        write_on_text(self.text_send, [info, ciphertext])


class ConfigTab(tk.Frame, object):
    def __init__(self, gui, client, parent):
        super(ConfigTab, self).__init__(parent)

        self.gui = gui
        self.client = client

        frame_tab = tk.Frame(self)
        frame_tab.grid(sticky='nswe', padx=15, pady=15)

        # ephemeral
        label_ephemeral = tk.Label(frame_tab, text='Ephemeral Key')
        label_ephemeral.grid(sticky='w')
        self.entry_ephemeral_config = tk.Entry(frame_tab)
        self.entry_ephemeral_config.grid(sticky='we')

        # hSub
        label_hsub = tk.Label(frame_tab, text='hSub Key')
        label_hsub.grid(sticky=tk.W, pady=(10, 0))
        self.entry_hsub_config = tk.Entry(frame_tab)
        self.entry_hsub_config.grid(sticky='we')

        # name
        label_name = tk.Label(frame_tab, text='Name')
        label_name.grid(sticky=tk.W, pady=(10, 0))
        self.entry_name_config = tk.Entry(frame_tab)
        self.entry_name_config.grid(sticky='we')

        buttons_row = frame_tab.grid_size()[1] + 1

        # config button
        self.button_config = tk.Button(frame_tab, text='Configure',
                                       command=lambda: self.send_config(self.entry_ephemeral_config.get().strip(),
                                                                        self.entry_hsub_config.get().strip(),
                                                                        self.entry_name_config.get().strip()))
        self.button_config.grid(row=buttons_row, sticky='w', pady=(10, 0))

        # delete button
        self.button_delete_config = tk.Button(frame_tab, text='Delete Nym', command=self.send_delete)
        self.button_delete_config.grid(row=buttons_row, sticky='e', pady=(10, 0))

        # message box
        frame_text = tk.LabelFrame(frame_tab, text='Nym Configuration Headers')
        frame_text.grid(sticky='we', pady=(10, 0))
        self.text_config = tk.Text(frame_text, height=29)
        self.text_config.grid(row=0, column=0)
        scrollbar = tk.Scrollbar(frame_text, command=self.text_config.yview)
        scrollbar.grid(row=0, column=1, sticky='ns')
        self.text_config['yscrollcommand'] = scrollbar.set

    def set_deleted_interface(self):
        self.gui.window_main.set_all_tabs_state(False, [self])
        self.entry_ephemeral_config.config(state=tk.DISABLED)
        self.entry_hsub_config.config(state=tk.DISABLED)
        self.entry_name_config.config(state=tk.DISABLED)
        self.button_config.config(state=tk.DISABLED)
        self.button_delete_config.config(state=tk.DISABLED)

    def send_config(self, ephemeral, hsub, name):
        if ephemeral or hsub or name:
            if tkMessageBox.askyesno('Confirm', 'Are you sure you want to configure the nym?'):
                success, info, ciphertext = self.client.send_config(ephemeral, hsub, name)
                write_on_text(self.text_config, [info, ciphertext])
        else:
            tkMessageBox.showinfo('Input Error', 'No changes provided')

    def send_delete(self):
        if tkMessageBox.askyesno('Confirm', 'Are you sure you want to delete the nym?'):
            success, info, ciphertext = self.client.send_delete()
            write_on_text(self.text_config, [info, ciphertext])
            if success:
                self.set_deleted_interface()


class UnreadCounterTab(tk.Frame, object):
    def __init__(self, gui, client, parent):
        super(UnreadCounterTab, self).__init__(parent)

        self.gui = gui
        self.client = client

        frame_tab = tk.Frame(self)
        frame_tab.grid(sticky='nswe', padx=15, pady=15)

        frame_retrieve = tk.Frame(frame_tab)
        frame_retrieve.grid(sticky='w')

        frame_list = tk.LabelFrame(frame_tab, text='Nyms With Unread Messages')
        frame_list.grid(sticky='we')
        self.list_unread = tk.Listbox(frame_list, height=39, width=70)
        self.list_unread.grid(row=0, column=0, sticky='we')
        scrollbar_list = tk.Scrollbar(frame_list, command=self.list_unread.yview)
        scrollbar_list.grid(row=0, column=1, sticky='nsew')
        self.list_unread['yscrollcommand'] = scrollbar_list.set

        self.update_unread_counter()

    def update_unread_counter(self):
        counter = self.client.count_unread_messages()
        self.list_unread.delete(0, tk.END)
        if counter:
            for nym, count in counter.iteritems():
                self.list_unread.insert(tk.END, nym + '(' + str(count) + ')')
        else:
            self.list_unread.insert(tk.END, 'No messages found')

if __name__ == '__main__':
    Gui().window_login.mainloop()