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
__version__ = '1.1.1'
__status__ = 'Prototype'

import Tkinter as tk
import ttk
import os
import re
import subprocess
import hashlib
import sys
import shutil
import tkMessageBox
import threading
import Queue
import time
import ConfigParser
from binascii import b2a_base64, a2b_base64

import gnupg
from passlib.utils.pbkdf2 import pbkdf2
from pyaxo import Axolotl

import aampy
import message


cfg = ConfigParser.ConfigParser()

BASE_FILES_PATH = '/usr/share/nymphemeral'
USER_PATH = os.path.expanduser('~')
NYMPHEMERAL_PATH = USER_PATH + '/.config/nymphemeral'
CONFIG_FILE = NYMPHEMERAL_PATH + '/nymphemeral.cfg'


def files_in_path(path):
    return [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]


def create_directory(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

class NymphemeralGUI():
    def __init__(self):
        self.is_debugging = None
        self.directory_base = None
        self.directory_db = None
        self.directory_read_messages = None
        self.directory_unread_messages = None
        self.file_hsub = None
        self.file_mix_binary = None
        self.file_mix_cfg = None
        self.check_base_files()

        self.aampy = aampy
        self.axolotl = None

        # attributes to handle aampy using threads
        self.event_aampy = None
        self.queue_ammpy = Queue.Queue()
        self.thread_event = None
        self.thread_aampy = None
        self.aampy_is_done = True
        self.id_after = None

        # attributes to decrypt messages using threads
        self.queue_pyaxo = Queue.Queue()
        self.thread_decrypt = None

        self.users = self.retrieve_users()
        self.address = None
        self.nym_server = None
        self.passphrase = None
        self.hsub = None
        self.fingerprint = None
        self.chain = None
        self.send_choice = None

        self.messages = []
        self.current_message_index = None

        self.gpg = None
        self.setup_gpg()
        self.keys = self.gpg.list_keys()
        self.servers = self.retrieve_servers()

        # login window
        self.window_login = None
        self.entry_address_login = None
        self.entry_passphrase_login = None

        # servers window
        self.window_servers = None
        self.list_servers = None
        self.button_modify_servers = None
        self.button_delete_servers = None

        # manage key window
        self.window_key = None

        # main window
        self.window_main = None
        self.notebook_login = None
        self.tab_decrypt = None
        self.tab_send = None
        self.tab_configure = None
        self.tab_create = None

        # decrypt tab
        self.button_aampy_decrypt = None
        self.progress_bar_decrypt = None
        self.list_messages_decrypt = None
        self.text_content_decrypt = None
        self.button_save_del_decrypt = None
        self.button_reply_decrypt = None
        self.label_save_del_decrypt = None

        # send tab
        self.entry_target_send = None
        self.entry_subject_send = None
        self.text_send = None

        # config tab
        self.entry_ephemeral_config = None
        self.entry_hsub_config = None
        self.entry_name_config = None
        self.text_config = None

        # create tab
        self.entry_ephemeral_create = None
        self.entry_hsub_create = None
        self.text_name_create = None
        self.text_duration_create = None
        self.button_create = None
        self.text_create = None

        self.build_login_window()

    def debug(self, info):
        if self.is_debugging:
            print info

    def load_configs(self):
        try:
            if not os.path.exists(CONFIG_FILE):
                cfg.add_section('main')
                cfg.set('main', 'base_folder', NYMPHEMERAL_PATH)
                cfg.set('main', 'db_folder', '%(base_folder)s/db')
                cfg.set('main', 'messages_folder', '%(base_folder)s/messages')
                cfg.set('main', 'read_folder', '%(messages_folder)s/read')
                cfg.set('main', 'unread_folder', '%(messages_folder)s/unread')
                cfg.set('main', 'hsub_file', '%(base_folder)s/hsubpass.txt')
                cfg.set('main', 'debug_switch', 'False')
                cfg.add_section('mixmaster')
                cfg.set('mixmaster', 'base_folder', USER_PATH + '/Mix')
                cfg.set('mixmaster', 'binary', '%(base_folder)s/mixmaster')
                cfg.set('mixmaster', 'cfg', '%(base_folder)s/mix.cfg')
                cfg.add_section('newsgroup')
                cfg.set('newsgroup', 'base_folder', NYMPHEMERAL_PATH)
                cfg.set('newsgroup', 'group', 'alt.anonymous.messages')
                cfg.set('newsgroup', 'server', 'localhost')
                cfg.set('newsgroup', 'port', '119')
                cfg.set('newsgroup', 'newnews', '%(base_folder)s/.newnews')
                create_directory(NYMPHEMERAL_PATH)
                with open(CONFIG_FILE, 'w') as config_file:
                    cfg.write(config_file)
            cfg.read(CONFIG_FILE)
            self.directory_base = cfg.get('main', 'base_folder')
            self.directory_db = cfg.get('main', 'db_folder')
            self.directory_read_messages = cfg.get('main', 'read_folder')
            self.directory_unread_messages = cfg.get('main', 'unread_folder')
            self.file_hsub = cfg.get('main', 'hsub_file')
            self.is_debugging = cfg.getboolean('main', 'debug_switch')
            self.file_mix_binary = cfg.get('mixmaster', 'binary')
            self.file_mix_cfg = cfg.get('mixmaster', 'cfg')
        except IOError:
            print 'Error while opening ' + str(CONFIG_FILE).split('/')[-1]
            raise

    def check_base_files(self):
        try:
            self.load_configs()
            create_directory(self.directory_db)
            shutil.copyfile(BASE_FILES_PATH + '/db/generic.db', self.directory_db + '/generic.db')
            create_directory(self.directory_read_messages)
            create_directory(self.directory_unread_messages)
        except IOError:
            print 'Error while creating the base files'
            raise

    def retrieve_mix_chain(self):
        chain = None
        try:
            with open(self.file_mix_cfg, 'r') as config:
                lines = config.readlines()
                for line in lines:
                    if line[:5] == 'CHAIN':
                        chain = 'Mix Chain: ' + line.replace('CHAIN ', '').strip()
        except IOError:
            self.debug('Error while manipulating ' + self.file_mix_cfg.split('/')[-1])
        return chain

    def close_all_windows(self):
        self.debug('Closing nymphemeral')
        self.window_login.destroy()
        self.window_main.destroy()

    def change_user(self):
        self.address = None
        self.passphrase = None
        self.hsub = None
        self.entry_address_login.delete(0, tk.END)
        self.entry_passphrase_login.delete(0, tk.END)
        if not self.aampy_is_done:
            self.window_main.after_cancel(self.id_after)
            self.progress_bar_decrypt.stop()
            self.event_aampy.set()
        self.window_main.destroy()
        self.window_login.deiconify()
        self.window_login.focus_force()
        self.entry_address_login.focus_set()

    def retrieve_users(self):
        users = {}
        try:
            if not os.path.exists(self.file_hsub):
                self.debug(
                    'Creating ' + self.file_hsub.split('/')[-1] + ' - aampy will download messages from last hour')
                time_stamp = time.time() - 3600.0
                with open(self.file_hsub, 'w') as file:
                    file.write('time ' + str(time_stamp) + '\n')
            users = self.aampy.readDict(self.file_hsub)
        except IOError:
            print 'Error while manipulating ' + self.file_hsub.split('/')[-1] + ':', sys.exc_info()[0]
        return users

    def add_user(self, address, hsub_key):
        try:
            if hsub_key not in self.users.values():
                self.users[address] = hsub_key
                self.aampy.writeDict(self.file_hsub, self.users)
                return True
        except IOError:
            print 'Error while manipulating ' + self.file_hsub.split('/')[-1] + ':', sys.exc_info()[0]
        return False

    def delete_user(self, address):
        try:
            del self.users[address]
            self.aampy.writeDict(self.file_hsub, self.users)
            return True
        except IOError:
            print 'Error while manipulating ' + self.file_hsub.split('/')[-1] + ':', sys.exc_info()[0]
        return False

    def retrieve_fingerprint(self, address):
        for item in self.keys:
            if address in item['uids'][0]:
                return item['fingerprint']
        return None

    def retrieve_servers(self):
        servers = {}
        for item in self.keys:
            config_match = None
            send_match = None
            url_match = None
            for uid in item['uids']:
                if not config_match:
                    config_match = re.search('[^( |<)]*config@[^( |>)]*', uid)
                if not send_match:
                    send_match = re.search('[^( |<)]*send@[^( |>)]*', uid)
                if not url_match:
                    url_match = re.search('[^( |<)]*url@[^( |>)]*', uid)
            if config_match and send_match and url_match:
                server = config_match.group(0).split('@')[1]
                servers[server] = item['fingerprint']
        return servers

    def start_session(self, event=None):
        if not re.match(r'[^@]+@[^@]+\.[^@]+', self.entry_address_login.get()):
            tkMessageBox.showerror('Invalid Email Address', 'Please verify the email address provided.')
            return
        self.address = self.entry_address_login.get().lower()
        self.nym_server = self.address.split('@')[1]
        self.passphrase = self.entry_passphrase_login.get()
        if self.nym_server not in self.servers:
            if tkMessageBox.askyesno('Server Not Found',
                                     self.nym_server + "'s public key was not found in the keyring.\n"
                                     'Would you like to add it right now?'):
                self.build_manage_key_window()
            return
        if self.address not in self.users:
            if not tkMessageBox.askyesno('Nym Not Found',
                                         'Would you like to create a nym with the following address?\n\n'
                                         + self.address):
                return
        else:
            self.hsub = self.users[self.address]
            self.fingerprint = self.retrieve_fingerprint(self.address)
            if not self.fingerprint:
                tkMessageBox.showerror('Fingerprint Not Found',
                                       'Fingerprint for this user was not found in the keyring.')
                return
            db_name = self.directory_db + '/' + self.fingerprint + '.db'
            try:
                self.axolotl = Axolotl(self.fingerprint, dbname=db_name, dbpassphrase=self.passphrase)
            except SystemExit:
                self.debug('Error while starting session')
                tkMessageBox.showerror('Database Error', 'Error when accessing the database.\nCheck the password!')
                return
        self.build_main_window()
        self.window_login.withdraw()

    def append_messages_to_list(self, user, from_encrypted_folder, messages_list):
        if from_encrypted_folder:
            path = self.directory_unread_messages
        else:
            path = self.directory_read_messages
        files = files_in_path(path)
        for file in files:
            if re.match('message_' + user + '_.*', file):
                file_path = path + '/' + file
                data = ''
                with open(file_path, 'r') as f:
                    for line in f:
                        data += line
                new_message = message.Message(from_encrypted_folder, data, file_path)
                messages_list.append(new_message)

    def retrieve_messages_from_disk(self, user):
        messages = []
        messages_without_date = []
        self.append_messages_to_list(user, False, messages)
        self.append_messages_to_list(user, True, messages)
        for i, m in enumerate(messages):
            if not m.date:
                messages_without_date.append(messages.pop(i))
        # Sort and display the newest messages first
        messages = sorted(messages, key=lambda item: item.date, reverse=True)
        messages += messages_without_date
        return messages

    def enable_tabs(self, user_exists):
        if user_exists:
            state = tk.NORMAL
        else:
            state = tk.DISABLED
        for index in range(3):
            self.notebook_login.tab(index, state=state)

    def build_login_window(self):
        self.window_login = tk.Tk()
        self.window_login.title('nymphemeral')
        self.window_login.bind('<Return>', self.start_session)

        frame_login = tk.Frame(self.window_login)
        frame_login.grid(sticky='w', padx=15, pady=15)

        # title
        label_title = tk.Label(frame_login, text='nymphemeral', font=('Helvetica', 26))
        label_title.grid(sticky='n')

        # address
        label_address = tk.Label(frame_login, text='Address')
        label_address.grid(sticky='w', pady=(15, 0))
        self.entry_address_login = tk.Entry(frame_login)
        self.entry_address_login.grid(sticky='we')

        # passphrase
        label_passphrase = tk.Label(frame_login, text='Passphrase')
        label_passphrase.grid(sticky='w', pady=(10, 0))
        self.entry_passphrase_login = tk.Entry(frame_login, show='*')
        self.entry_passphrase_login.grid(sticky='we')

        # servers
        button_servers = tk.Button(frame_login, text='Manage Servers', command=self.build_servers_window)
        button_servers.grid(pady=(5, 0))

        # output radio buttons
        frame_radio = tk.LabelFrame(frame_login, text='Output Method')
        frame_radio.grid(pady=(10, 0), ipadx=5, ipady=5, sticky='we')
        self.send_choice = tk.IntVar()
        radio_mix = tk.Radiobutton(frame_radio, text='Send via Mixmaster', variable=self.send_choice, value=1)
        radio_mix.grid(pady=(5, 0), sticky='w')
        chain = self.retrieve_mix_chain()
        self.chain = chain
        if not chain:
            radio_mix.config(state=tk.DISABLED)
            chain = 'Error while manipulating mix.cfg'
        label_chain = tk.Label(frame_radio, text=chain)
        label_chain.grid(sticky='w', padx=(25, 0))
        radio_email = tk.Radiobutton(frame_radio, text='Send via Email', variable=self.send_choice, value=2)
        radio_email.grid(sticky='w')
        radio_text = tk.Radiobutton(frame_radio, text='Display Output in Message Window',
                                    variable=self.send_choice,
                                    value=3)
        radio_text.grid(sticky='w')
        self.send_choice.set(3)

        # start button
        button_start = tk.Button(frame_login, text='Start Session', command=self.start_session)
        button_start.grid(pady=(15, 0))

        self.entry_address_login.focus_set()

    def build_servers_window(self):
        self.window_servers = tk.Tk()
        self.window_servers.title('Nym Servers')

        frame_servers = tk.Frame(self.window_servers)
        frame_servers.grid(sticky='w', padx=15, pady=15)

        # servers list box
        frame_list = tk.LabelFrame(frame_servers, text='Nym Servers')
        frame_list.grid(sticky='we')
        self.list_servers = tk.Listbox(frame_list, height=11, width=40)
        self.list_servers.grid(row=0, column=0, sticky='we')
        scrollbar_list = tk.Scrollbar(frame_list, command=self.list_servers.yview)
        scrollbar_list.grid(row=0, column=1, sticky='nsew')
        self.list_servers['yscrollcommand'] = scrollbar_list.set
        self.list_servers.bind('<<ListboxSelect>>', self.toggle_server_interface)

        buttons_row = frame_servers.grid_size()[1] + 1

        # new button
        button_new_servers = tk.Button(frame_servers, text='New', command=self.build_manage_key_window)
        button_new_servers.grid(row=buttons_row, sticky='w', pady=(10, 0))

        # modify button
        self.button_modify_servers = tk.Button(frame_servers, text='Modify',
                                               command=lambda: self.build_manage_key_window(
                                                   self.list_servers.get(self.list_servers.curselection())),
                                               state=tk.DISABLED)
        self.button_modify_servers.grid(row=buttons_row, pady=(10, 0))

        # delete button
        self.button_delete_servers = tk.Button(frame_servers, text='Delete',
                                               command=lambda: self.delete_key(
                                                   self.list_servers.get(self.list_servers.curselection())),
                                               state=tk.DISABLED)
        self.button_delete_servers.grid(row=buttons_row, sticky='e', pady=(10, 0))

        self.update_servers_list()

    def build_manage_key_window(self, server=None):
        self.window_key = tk.Tk()
        self.window_key.title('Public Key Manager')

        frame_key = tk.Frame(self.window_key)
        frame_key.grid(sticky='w', padx=15, pady=15)

        # key text box
        key = ''
        if server:
            frame_list = tk.LabelFrame(frame_key, text=server + "'s Public Key")
            key = self.gpg.export_keys(self.servers[server])
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
                                    command=lambda: self.save_key(server, text_key.get(1.0, tk.END)))
        button_save_key.grid(pady=(10, 0))

        text_key.mark_set(tk.INSERT, 1.0)
        text_key.focus_set()

    def build_main_window(self):
        if self.hsub:
            user_exists = True
        else:
            user_exists = False

        # root window
        self.window_main = tk.Tk()
        self.window_main.title('nymphemeral')

        # frame inside root window
        frame_tab = tk.Frame(self.window_main)
        frame_tab.pack()

        # tabs
        self.notebook_login = ttk.Notebook(frame_tab)
        self.notebook_login.pack()

        self.tab_decrypt = tk.Frame(self.notebook_login)
        self.notebook_login.add(self.tab_decrypt, text='Decrypt Message')
        self.build_decrypt_tab()
        self.tab_send = tk.Frame(self.notebook_login)
        self.notebook_login.add(self.tab_send, text='Send Message')
        self.build_send_tab()
        self.tab_configure = tk.Frame(self.notebook_login)
        self.notebook_login.add(self.tab_configure, text='Configure Nym')
        self.build_config_tab()
        if not user_exists:
            self.tab_create = tk.Frame(self.notebook_login)
            self.notebook_login.add(self.tab_create, text='Create Nym')
            self.build_create_tab()
        self.notebook_login.pack(fill=tk.BOTH, expand=True)
        self.enable_tabs(user_exists)

        # footer
        frame_footer = tk.Frame(frame_tab)
        frame_footer.pack(fill=tk.X, expand=True, padx=5, pady=5)

        frame_left = tk.Frame(frame_footer)
        frame_left.pack(side=tk.LEFT)
        frame_address = tk.Frame(frame_left)
        frame_address.pack(fill=tk.X, expand=True)
        label_address = tk.Label(frame_address, text=self.address)
        label_address.pack(side=tk.LEFT)
        if self.send_choice.get() is 1:
            frame_chain = tk.Frame(frame_left)
            frame_chain.pack(fill=tk.X, expand=True)
            label_chain = tk.Label(frame_chain, text=self.chain)
            label_chain.pack(side=tk.LEFT)
        button_change_user = tk.Button(frame_footer, text='Change User', command=self.change_user)
        button_change_user.pack(side=tk.RIGHT)

        # when the user closes self.window_main, closeAll() is called to close the login window as well
        self.window_main.protocol('WM_DELETE_WINDOW', self.close_all_windows)

        # move window to the center
        self.window_main.update_idletasks()
        window_w, window_h = self.window_main.winfo_width(), self.window_main.winfo_height()
        screen_w, screen_h = self.window_main.winfo_screenwidth(), self.window_main.winfo_screenheight()
        self.window_main.geometry('%dx%d+%d+%d'
                                  % (window_w, window_h, (screen_w - window_w) / 2, (screen_h - window_h) / 2))

    def build_create_tab(self):
        frame_tab = tk.Frame(self.tab_create)
        frame_tab.grid(sticky='nswe', padx=15, pady=15)

        # ephemeral
        label_ephemeral = tk.Label(frame_tab, text='Ephemeral Key')
        label_ephemeral.grid(sticky='w')
        self.entry_ephemeral_create = tk.Entry(frame_tab)
        self.entry_ephemeral_create.grid(sticky='we')

        # hSub
        label_hsub = tk.Label(frame_tab, text='hSub Key')
        label_hsub.grid(sticky=tk.W, pady=(10, 0))
        self.entry_hsub_create = tk.Entry(frame_tab)
        self.entry_hsub_create.grid(sticky='we')

        # name
        label_name = tk.Label(frame_tab, text='Name')
        label_name.grid(sticky=tk.W, pady=(10, 0))
        self.text_name_create = tk.Entry(frame_tab)
        self.text_name_create.grid(sticky='we')

        # duration
        label_duration = tk.Label(frame_tab, text='Duration')
        label_duration.grid(sticky=tk.W, pady=(10, 0))
        self.text_duration_create = tk.Entry(frame_tab)
        self.text_duration_create.grid(sticky='we')

        # create button
        self.button_create = tk.Button(frame_tab, text='Create Nym', command=self.send_create)
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

    def build_send_tab(self):
        frame_tab = tk.Frame(self.tab_send)
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
        button_send = tk.Button(frame_tab, text='Send', command=self.send_message)
        button_send.grid()

    def build_decrypt_tab(self):
        frame_tab = tk.Frame(self.tab_decrypt)
        frame_tab.grid(sticky='nswe', padx=15, pady=15)

        frame_retrieve = tk.Frame(frame_tab)
        frame_retrieve.grid(sticky='w', pady=(0, 10))

        # retrieve button
        self.button_aampy_decrypt = tk.Button(frame_retrieve, width=14, text='Retrieve Messages',
                                              command=self.retrieve_messages_from_aam)
        self.button_aampy_decrypt.grid(row=0, sticky='w')

        # progress bar
        self.progress_bar_decrypt = ttk.Progressbar(frame_retrieve, mode='indeterminate', length=427)

        # messages list box
        frame_list = tk.LabelFrame(frame_tab, text='Messages')
        frame_list.grid(sticky='we')
        self.list_messages_decrypt = tk.Listbox(frame_list, height=11, width=70)
        self.list_messages_decrypt.grid(row=0, column=0, sticky='we')
        scrollbar_list = tk.Scrollbar(frame_list, command=self.list_messages_decrypt.yview)
        scrollbar_list.grid(row=0, column=1, sticky='nsew')
        self.list_messages_decrypt['yscrollcommand'] = scrollbar_list.set
        self.list_messages_decrypt.bind('<<ListboxSelect>>', self.select_message)

        # content list box
        frame_text = tk.LabelFrame(frame_tab, text='Content')
        frame_text.grid(pady=10, sticky='we')
        self.text_content_decrypt = tk.Text(frame_text, height=22)
        self.text_content_decrypt.grid(row=0, column=0, sticky='we')
        scrollbar_text = tk.Scrollbar(frame_text, command=self.text_content_decrypt.yview)
        scrollbar_text.grid(row=0, column=1, sticky='nsew')
        self.text_content_decrypt['yscrollcommand'] = scrollbar_text.set

        buttons_row = frame_tab.grid_size()[1] + 1

        # save/delete button
        self.button_save_del_decrypt = tk.Button(frame_tab, text='Save to Disk', command=self.save_message_to_disk)
        self.button_save_del_decrypt.grid(row=buttons_row, sticky='w', pady=(10, 0))

        # reply button
        self.button_reply_decrypt = tk.Button(frame_tab, text='Reply Message', command=self.reply_message)
        self.button_reply_decrypt.grid(row=buttons_row, sticky='e', pady=(10, 0))

        # notification label
        self.label_save_del_decrypt = tk.Label(frame_tab)
        self.label_save_del_decrypt.grid(row=buttons_row, pady=(10, 0))

        self.load_messages()

    def build_config_tab(self):
        frame_tab = tk.Frame(self.tab_configure)
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
        button_config = tk.Button(frame_tab, text='Configure', command=self.send_config)
        button_config.grid(row=buttons_row, sticky='w', pady=(10, 0))

        # delete button
        button_delete_config = tk.Button(frame_tab, text='Delete Nym', command=self.send_delete)
        button_delete_config.grid(row=buttons_row, sticky='e', pady=(10, 0))

        # message box
        frame_text = tk.LabelFrame(frame_tab, text='Nym Configuration Headers')
        frame_text.grid(sticky='we', pady=(10, 0))
        self.text_config = tk.Text(frame_text, height=29)
        self.text_config.grid(row=0, column=0)
        scrollbar = tk.Scrollbar(frame_text, command=self.text_config.yview)
        scrollbar.grid(row=0, column=1, sticky='ns')
        self.text_config['yscrollcommand'] = scrollbar.set

    def toggle_server_interface(self, event=None):
        if event:
            self.button_modify_servers.config(state=tk.NORMAL)
            self.button_delete_servers.config(state=tk.NORMAL)
        else:
            self.button_modify_servers.config(state=tk.DISABLED)
            self.button_delete_servers.config(state=tk.DISABLED)

    def manage_current_server(self):
        if self.list_servers.curselection():
            self.build_manage_key_window(self.list_servers.get(self.list_servers.curselection()))

    def save_key(self, server, key):
        if server:
            self.gpg.delete_keys(self.servers[server])
        self.gpg.import_keys(key)
        self.keys = self.gpg.list_keys()
        self.servers = self.retrieve_servers()
        if self.list_servers:
            self.update_servers_list()
        self.window_key.destroy()

    def delete_key(self, server):
        if tkMessageBox.askyesno('Confirm', 'Are you sure you want to delete ' + server + "'s key?"):
            self.gpg.delete_keys(self.servers[server])
            self.keys = self.gpg.list_keys()
            self.servers = self.retrieve_servers()
            self.update_servers_list()

    def update_servers_list(self):
        self.list_servers.delete(0, tk.END)
        for s in self.servers.keys():
            self.list_servers.insert(tk.END, s)
        self.toggle_server_interface()

    def update_messages_list(self):
        self.disable_decrypt_interface(False)
        self.list_messages_decrypt.delete(0, tk.END)
        for m in self.messages:
            self.list_messages_decrypt.insert(tk.END, m.title)

    def load_messages(self):
        self.messages = self.retrieve_messages_from_disk(self.address)
        self.current_message_index = None
        self.update_messages_list()

    def wait_for_aampy(self):
        self.aampy_is_done = False
        self.event_aampy.wait()
        self.aampy_is_done = True

    def wait_for_event(self):
        if self.aampy_is_done:
            if self.queue_ammpy.get():
                self.load_messages()
            else:
                self.disable_decrypt_interface(False)
                tkMessageBox.showerror('Socket Error', 'The news server cannot be found!')
        else:
            self.id_after = self.window_main.after(1000, self.wait_for_event)

    def disable_decrypt_interface(self, aampy_is_running):
        self.button_save_del_decrypt.config(state=tk.DISABLED)
        self.button_reply_decrypt.config(state=tk.DISABLED)
        self.toggle_aampy_button(aampy_is_running)
        if aampy_is_running:
            self.list_messages_decrypt.config(state=tk.DISABLED)
            self.text_content_decrypt.config(state=tk.DISABLED)
            self.progress_bar_decrypt.grid(row=0, column=1, sticky='nswe', padx=(15, 0))
            self.progress_bar_decrypt.start(25)
        else:
            self.list_messages_decrypt.config(state=tk.NORMAL)
            self.text_content_decrypt.config(state=tk.NORMAL)
            self.progress_bar_decrypt.stop()
            self.progress_bar_decrypt.grid_forget()

    def retrieve_messages_from_aam(self):
        try:
            self.disable_decrypt_interface(True)
            self.event_aampy = threading.Event()
            self.thread_event = threading.Thread(target=self.wait_for_aampy)
            self.thread_event.daemon = True
            self.thread_aampy = threading.Thread(target=self.aampy.aam, args=(self.event_aampy, self.queue_ammpy, cfg))
            self.thread_aampy.daemon = True
            self.thread_event.start()
            self.thread_aampy.start()
            self.wait_for_event()
        except:
            print 'Error while retrieving messages' + ':', sys.exc_info()[0]

    def stop_retrieving_messages(self):
        self.event_aampy.set()
        self.update_messages_list()

    def send_create(self):
        duration = self.text_duration_create.get()
        passphrase = self.passphrase
        name = self.text_name_create.get()
        address = self.address
        ephemeral = self.entry_ephemeral_create.get().strip()
        hsub = self.entry_hsub_create.get().strip()
        send_choice = self.send_choice.get()
        recipient = 'config@' + self.nym_server

        if not len(hsub):
            tkMessageBox.showerror('hSub Key Not Found', 'This client requires you to use an hSub key.')
            return

        input_data = self.gpg.gen_key_input(key_type='RSA', key_length='4096',
                                            subkey_type='RSA', subkey_length='4096',
                                            key_usage='sign,auth', subkey_usage='encrypt',
                                            expire_date=duration, passphrase=passphrase,
                                            name_real=name, name_comment='', name_email=address)
        self.gpg.gen_key(input_data)
        self.keys = self.gpg.list_keys()
        pubkey = self.gpg.export_keys(keyids=address)
        fingerprint = self.retrieve_fingerprint(address)
        self.fingerprint = fingerprint

        data = 'ephemeral: ' + ephemeral + '\nhsub: ' + hsub + '\n' + pubkey

        self.generate_db(fingerprint, ephemeral, passphrase)

        if self.encrypt_and_send(data, recipient, fingerprint, passphrase, send_choice, self.text_create):
            self.add_user(address, hsub)
            self.hsub = hsub
            db_name = self.directory_db + '/' + self.fingerprint + '.db'
            self.axolotl = Axolotl(self.fingerprint, dbname=db_name, dbpassphrase=passphrase)

            self.enable_tabs(True)
            self.entry_ephemeral_create.config(state=tk.DISABLED)
            self.entry_hsub_create.config(state=tk.DISABLED)
            self.text_name_create.config(state=tk.DISABLED)
            self.text_duration_create.config(state=tk.DISABLED)
            self.button_create.config(state=tk.DISABLED)

    def send_message(self):
        passphrase = self.passphrase
        fingerprint = self.fingerprint
        target_address = self.entry_target_send.get().lower()
        subject = self.entry_subject_send.get()
        send_choice = self.send_choice.get()
        content = self.text_send.get(1.0, tk.END)
        recipient = 'send@' + self.nym_server
        msg = 'To: ' + target_address + '\nSubject: ' + subject + '\n\n' + content

        self.axolotl.loadState(fingerprint, 'a')
        ciphertext = b2a_base64(self.axolotl.encrypt(msg)).strip()
        self.axolotl.saveState()

        lines = [ciphertext[i:i + 64] for i in xrange(0, len(ciphertext), 64)]
        pgp_message = '-----BEGIN PGP MESSAGE-----\n\n'
        for line in lines:
            pgp_message += line + '\n'
        pgp_message += '-----END PGP MESSAGE-----\n'

        self.encrypt_and_send(pgp_message, recipient, fingerprint, passphrase, send_choice, self.text_send)

    def send_config(self):
        address = self.address
        passphrase = self.passphrase
        send_choice = self.send_choice.get()
        fingerprint = self.fingerprint
        db_file = self.directory_db + '/' + fingerprint + '.db'
        recipient = 'config@' + self.nym_server
        reset_db = False
        reset_hsub = False

        ephemeral = self.entry_ephemeral_config.get().strip()
        hsub = self.entry_hsub_config.get().strip()
        name = self.entry_name_config.get().strip()

        ephemeral_line = ''
        hsub_line = ''
        name_line = ''

        if ephemeral is not '':
            ephemeral_line = 'ephemeral: ' + ephemeral + '\n'
            reset_db = True
        if hsub is not '':
            hsub_line = 'hsub: ' + hsub + '\n'
            reset_hsub = True
        if name is not '':
            name_line = 'name: ' + name + '\n'

        data = ephemeral_line + hsub_line + name_line
        if data is not '':
            if self.encrypt_and_send(data, recipient, fingerprint, passphrase, send_choice, self.text_config):
                if reset_db:
                    if os.path.exists(db_file):
                        os.unlink(db_file)
                    self.generate_db(fingerprint, ephemeral, passphrase)
                if reset_hsub:
                    self.add_user(address, hsub)

    def send_delete(self):
        address = self.address
        if tkMessageBox.askyesno('Confirm', 'Are you sure you want to delete "' + address + '"?'):
            passphrase = self.passphrase
            send_choice = self.send_choice.get()
            fingerprint = self.fingerprint
            db_file = self.directory_db + '/' + fingerprint + '.db'
            recipient = 'config@' + self.nym_server

            data = 'delete: yes'
            if self.encrypt_and_send(data, recipient, fingerprint, passphrase, send_choice, self.text_config):
                if os.path.exists(db_file):
                    os.unlink(db_file)
                self.delete_user(address)
                self.gpg.delete_keys(fingerprint, True)
                self.gpg.delete_keys(fingerprint)
                self.keys = self.gpg.list_keys()
                if send_choice is not 3:
                    self.change_user()

    def encrypt_and_send(self, data, recipient, fingerprint, passphrase, send_choice, target_text):
        success = False
        ciphertext = self.gpg.encrypt(data, recipients=recipient,
                                      sign=fingerprint, passphrase=passphrase, always_trust=True)
        if str(ciphertext) is None or str(ciphertext) == '':
            tkMessageBox.showerror('Message Not Sent', 'Bad nym passphrase!')
        else:
            success = True
            if send_choice == 3:
                info = 'Send the following message to ' + recipient
                if self.copy_pgp_message(str(ciphertext)):
                    info += '\nIt has been copied to the clipboard'
            else:
                data = 'To: ' + recipient + '\nSubject: test\n\n' + str(ciphertext)
                if self.send_data(data, send_choice):
                    info = 'The following message was successfully sent'
                else:
                    info = 'ERROR! The following message could not be sent'
                    success = False
            info += '\n\n'
            target_text.delete(1.0, tk.END)
            target_text.insert(tk.INSERT, info)
            target_text.insert(tk.INSERT, str(ciphertext))
        return success

    def decrypt_message(self, fingerprint, data):
        ciphertext = None
        try:
            self.axolotl.loadState(fingerprint, 'a')
            ciphertext = self.axolotl.decrypt(a2b_base64(data)).strip()
            self.axolotl.saveState()
        except SystemExit:
            self.debug('Error while decrypting message')
        self.queue_pyaxo.put(ciphertext)

    def select_message(self, event):
        if self.aampy_is_done and len(self.messages):
            widget = event.widget
            index = int(widget.curselection()[0])
            selected_message = self.messages[index]
            self.current_message_index = index

            self.text_content_decrypt.delete(1.0, tk.END)

            if selected_message.is_encrypted:
                self.button_save_del_decrypt.config(state=tk.DISABLED)
                self.button_reply_decrypt.config(state=tk.DISABLED)
                passphrase = self.passphrase
                fingerprint = self.fingerprint
                exp = re.compile('^[A-Za-z0-9+\/=]+\Z')
                buf = selected_message.content.splitlines()
                msg = ''
                for item in buf:
                    if len(item.strip()) % 4 == 0 and exp.match(item) and len(
                            item.strip()) <= 64 and not item.startswith(' '):
                        msg += item
                self.thread_decrypt = threading.Thread(target=self.decrypt_message, args=(fingerprint, msg, ))
                self.thread_decrypt.start()
                self.thread_decrypt.join()
                ciphertext = self.queue_pyaxo.get()
                self.delete_message_from_disk()
                if ciphertext:
                    plaintext = str(self.gpg.decrypt(ciphertext, passphrase=passphrase, always_trust=True))
                    if not len(plaintext):
                        plaintext = 'The message could not be decrypted by GPG. Ciphertext:\n\n' + ciphertext
                    m = message.Message(False, plaintext, selected_message.identifier)
                    self.text_content_decrypt.insert(tk.INSERT, m.content)
                    self.messages[index] = m
                    self.update_messages_list()
                    self.toggle_save_del_button(True)
                    self.button_save_del_decrypt.config(state=tk.NORMAL)
                    self.button_reply_decrypt.config(state=tk.NORMAL)
                    self.debug('Message decrypted')
                else:
                    tkMessageBox.showerror('Undecipherable Message',
                                           'The message could not be deciphered.')
                    self.messages.pop(index)
                    self.current_message_index = None
                    self.update_messages_list()
            else:
                if self.check_message_in_disk():
                    self.toggle_save_del_button(False)
                else:
                    self.toggle_save_del_button(True)
                self.text_content_decrypt.insert(tk.INSERT, selected_message.content)
                self.button_save_del_decrypt.config(state=tk.NORMAL)
                self.button_reply_decrypt.config(state=tk.NORMAL)

    def check_message_in_disk(self):
        msg = self.messages[self.current_message_index]
        if os.path.exists(msg.identifier):
            return True
        else:
            return False

    def save_message_to_disk(self):
        try:
            msg = self.messages[self.current_message_index]
            new_identifier = self.directory_read_messages + '/' + msg.identifier.split('/')[-1]
            with open(new_identifier, 'w') as file:
                file.write(msg.processed_message.as_string())
                self.messages[self.current_message_index].identifier = new_identifier
                self.debug('Message saved to disk')
                return True
        except IOError:
            print 'Error while saving to disk' + ':', sys.exc_info()[0]
        return False

    def delete_message_from_disk(self):
        try:
            msg = self.messages[self.current_message_index]
            if os.path.exists(msg.identifier):
                os.unlink(msg.identifier)
                self.debug('Message deleted from disk')
            return True
        except IOError:
            print 'Error while deleting from disk' + ':', sys.exc_info()[0]
        return False

    def toggle_save_del_button(self, toggle_save):
        if toggle_save:
            self.button_save_del_decrypt.config(text='Save to Disk', command=self.save_and_update_interface)
        else:
            self.button_save_del_decrypt.config(text='Delete from Disk', command=self.delete_and_update_interface)

    def save_and_update_interface(self):
        if self.save_message_to_disk():
            self.toggle_save_del_button(False)
            self.show_label_save_del('Message saved')

    def delete_and_update_interface(self):
        if self.delete_message_from_disk():
            self.toggle_save_del_button(True)
            self.show_label_save_del('Message deleted')

    def show_label_save_del(self, text):
        self.label_save_del_decrypt.config(text=text)
        self.window_main.after(3000, lambda: self.label_save_del_decrypt.config(text=''))

    def toggle_aampy_button(self, toggle_stop):
        if toggle_stop:
            self.button_aampy_decrypt.config(text='Stop', command=self.stop_retrieving_messages)
        else:
            self.button_aampy_decrypt.config(text='Retrieve Messages', command=self.retrieve_messages_from_aam)

    def reply_message(self):
        msg = self.messages[self.current_message_index]
        self.entry_target_send.delete(0, tk.END)
        if msg.sender:
            self.entry_target_send.insert(0, msg.sender.lower())
        self.entry_subject_send.delete(0, tk.END)
        if msg.subject:
            self.entry_subject_send.insert(0, 'Re: ' + msg.subject)
        content = '\n\n'
        for line in msg.content.splitlines():
            content += '> ' + line + '\n'
        self.text_send.delete(1.0, tk.END)
        self.text_send.insert(tk.INSERT, content)
        self.text_send.mark_set(tk.INSERT, 1.0)
        self.notebook_login.select(1)
        self.text_send.focus_set()

    def copy_pgp_message(self, data):
        re_pgp = re.compile('-----BEGIN PGP MESSAGE-----.*-----END PGP MESSAGE-----', flags=re.DOTALL)
        m = re_pgp.search(data)
        if m:
            self.window_login.clipboard_clear()
            self.window_login.clipboard_append(m.group())
            return True
        return False

    def setup_gpg(self):
        home = self.directory_base
        binary = '/usr/bin/gpg'
        keyring = [home + '/pubring.gpg', USER_PATH + '/.gnupg/pubring.gpg']
        wecret_keyring = [home + '/secring.gpg', USER_PATH + '/.gnupg/secring.gpg']
        self.gpg = gnupg.GPG(gnupghome=home, gpgbinary=binary, keyring=keyring,
                             secret_keyring=wecret_keyring, options=['--personal-digest-preferences=sha256',
                                                                     '--s2k-digest-algo=sha256'])
        self.gpg.encoding = 'latin-1'

    def send_data(self, data, send_choice):
        if send_choice == 1:
            p = subprocess.Popen([self.file_mix_binary, '-m'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        elif send_choice == 2:
            p = subprocess.Popen(['sendmail', '-t'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        else:
            self.debug('Invalid send choice')
            return False
        output, output_error = p.communicate(data)
        if output_error:
            return False
        if output or output == '':
            return True

    def generate_db(self, fingerprint, mkey, passphrase):
        mkey = hashlib.sha256(mkey).digest()
        dbname = self.directory_db + '/generic.db'
        a = Axolotl('b', dbname=dbname, dbpassphrase=None)
        a.loadState('b', 'a')
        a.dbname = self.directory_db + '/' + fingerprint + '.db'
        a.dbpassphrase = passphrase
        if a.mode:  # alice mode
            RK = pbkdf2(mkey, b'\x00', 10, prf='hmac-sha256')
            HKs = pbkdf2(mkey, b'\x01', 10, prf='hmac-sha256')
            HKr = pbkdf2(mkey, b'\x02', 10, prf='hmac-sha256')
            NHKs = pbkdf2(mkey, b'\x03', 10, prf='hmac-sha256')
            NHKr = pbkdf2(mkey, b'\x04', 10, prf='hmac-sha256')
            CKs = pbkdf2(mkey, b'\x05', 10, prf='hmac-sha256')
            CKr = pbkdf2(mkey, b'\x06', 10, prf='hmac-sha256')
            CONVid = pbkdf2(mkey, b'\x07', 10, prf='hmac-sha256')
        else:  # bob mode
            RK = pbkdf2(mkey, b'\x00', 10, prf='hmac-sha256')
            HKs = pbkdf2(mkey, b'\x02', 10, prf='hmac-sha256')
            HKr = pbkdf2(mkey, b'\x01', 10, prf='hmac-sha256')
            NHKs = pbkdf2(mkey, b'\x04', 10, prf='hmac-sha256')
            NHKr = pbkdf2(mkey, b'\x03', 10, prf='hmac-sha256')
            CKs = pbkdf2(mkey, b'\x06', 10, prf='hmac-sha256')
            CKr = pbkdf2(mkey, b'\x05', 10, prf='hmac-sha256')
            CONVid = pbkdf2(mkey, b'\x07', 10, prf='hmac-sha256')

        a.state['RK'] = RK
        a.state['HKs'] = HKs
        a.state['HKr'] = HKr
        a.state['NHKs'] = NHKs
        a.state['NHKr'] = NHKr
        a.state['CKs'] = CKs
        a.state['CKr'] = CKr
        a.state['CONVid'] = CONVid
        a.state['name'] = fingerprint
        a.state['other_name'] = 'a'

        with a.db:
            cur = a.db.cursor()
            cur.execute('DELETE FROM conversations WHERE my_identity = "b"')
            a.saveState()


if __name__ == '__main__':
    win = NymphemeralGUI()
    win.window_login.mainloop()