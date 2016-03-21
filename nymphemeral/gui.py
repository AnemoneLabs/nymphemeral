#!/usr/bin/env python
import logging
import operator
import os
import sys
import Tkinter as Tk
import tkMessageBox
import tkSimpleDialog
import ttk

from . import __version__
from . import errors
from . import LINESEP
from .client import DEBUG_LOGGER_LEVEL, OUTPUT_METHOD
from .client import format_key_info
from .client import retrieve_key, retrieve_keyids, search_pgp_message
from .client import Client
from .nym import Nym

log = logging.getLogger(__name__)


def write_on_text(text, content, clear=True):
    state = text.cget('state')
    text.config(state=Tk.NORMAL)
    if clear:
        text.delete(1.0, Tk.END)
    for c in content:
        text.insert(Tk.INSERT, c)
    text.config(state=state)


def set_widget_state(enable, widget):
    if enable:
        state = Tk.NORMAL
    else:
        state = Tk.DISABLED
    widget.config(state=state)


def bind_handler_to_widget_events(handler, widget, events):
    for event in events:
        widget.bind(event, handler)


def bind_checkbutton_and_entry(checkbutton, entry, enable=False):
    def handler(event):
        state = checkbutton.var.get()
        if enable:
            state = not state
        set_widget_state(state, entry)
    events = ['<Return>', '<Key-space>', '<Button-1>']
    bind_handler_to_widget_events(handler, checkbutton, events)


class Gui:
    def __init__(self):
        self.client = Client()
        self.title = 'nymphemeral'
        if self.client.logger_level == DEBUG_LOGGER_LEVEL:
            self.title += ' ' + __version__

        self.window_login = LoginWindow(self, self.client)
        self.window_main = None

        log.debug('Initialized')

    def start_session(self, creating_nym):
        self.window_login.destroy()
        self.window_login = None
        self.window_main = MainWindow(self, self.client, creating_nym)

    def end_session(self):
        if self.client.aampy.is_running:
            self.window_main.stop_retrieving_messages()
        self.client.end_session()
        self.window_main.destroy()
        self.window_main = None
        self.window_login = LoginWindow(self, self.client)


class LoginWindow(Tk.Tk, object):
    def __init__(self, gui, client):
        super(LoginWindow, self).__init__()

        self.gui = gui
        self.client = client
        self.var_output_method = None
        self.var_use_agent = Tk.BooleanVar()

        self.title(self.gui.title)
        frame_login = Tk.Frame(self)
        frame_login.grid(sticky='w', padx=15, pady=15)

        # title
        label_title = Tk.Label(frame_login, text='nymphemeral', font=('Helvetica', 26))
        label_title.grid(sticky='n')

        # address
        label_address = Tk.Label(frame_login, text='Address')
        label_address.grid(sticky='w', pady=(15, 0))
        entry_address_login = Tk.Entry(frame_login)
        entry_address_login.grid(sticky='we')

        # passphrase
        label_passphrase = Tk.Label(frame_login, text='Passphrase')
        label_passphrase.grid(sticky='w', pady=(10, 0))
        entry_passphrase_login = Tk.Entry(frame_login, show='*')
        entry_passphrase_login.grid(sticky='we')

        # start button
        button_start = Tk.Button(
            frame_login, text='Start Session',
            command=lambda: self.start_session(entry_address_login.get(),
                                               entry_passphrase_login.get()))
        button_start.grid(pady=(15, 0))
        self.bind('<Return>', lambda event: self.start_session(
            entry_address_login.get(),
            entry_passphrase_login.get()))

        # GPG agent checkbox
        check_agent = Tk.Checkbutton(frame_login, text='Use GPG Agent', variable=self.var_use_agent)
        check_agent.grid(sticky='w', padx=0, pady=(10, 0))
        self.var_use_agent.set(self.client.use_agent)

        # output radio buttons
        frame_radio = Tk.LabelFrame(frame_login, text='Output Method')
        frame_radio.grid(pady=(10, 0), ipadx=5, ipady=5, sticky='we')
        self.var_output_method = Tk.IntVar()
        if not self.client.file_mix_binary:
            text = 'Binary Not Found or Inappropriate'
            mix_state = Tk.DISABLED
        elif not self.client.file_mix_cfg:
            text = 'Config File Not Found'
            mix_state = Tk.DISABLED
        else:
            text = self.client.chain_info
            mix_state = Tk.NORMAL
        radio_mix = Tk.Radiobutton(frame_radio,
                                   text='Send via Mixmaster',
                                   variable=self.var_output_method,
                                   value=OUTPUT_METHOD['mixmaster'],
                                   state=mix_state)
        radio_mix.grid(pady=(5, 0), sticky='w')
        label_mix = Tk.Label(frame_radio, state=mix_state, text=text)
        label_mix.grid(sticky='w', padx=(25, 0))
        radio_email = Tk.Radiobutton(frame_radio, text='Send via Email', variable=self.var_output_method,
                                     value=OUTPUT_METHOD['sendmail'])
        radio_email.grid(sticky='w')
        radio_text = Tk.Radiobutton(frame_radio, text='Display Output in Message Window',
                                    variable=self.var_output_method,
                                    value=OUTPUT_METHOD['manual'])
        radio_text.grid(sticky='w')
        self.var_output_method.set(OUTPUT_METHOD[self.client.output_method])

        # servers
        button_servers = Tk.Button(frame_login, text='Manage Servers',
                                   command=lambda: ServersWindow(self.gui,
                                                                 self.client))
        button_servers.grid(pady=(10, 0))

        entry_address_login.focus_set()

    def get_output_method(self):
        for key, i in OUTPUT_METHOD.iteritems():
            if i == self.var_output_method.get():
                return key

    def start_session(self, address, passphrase, creating_nym=False):
        use_agent = bool(self.var_use_agent.get())
        method = self.get_output_method()
        try:
            nym = Nym(address, passphrase)
            if not len(passphrase):
                raise errors.InvalidPassphraseError()
            self.client.start_session(nym, use_agent, method, creating_nym)
        except (errors.InvalidEmailAddressError, errors.InvalidPassphraseError, errors.FingerprintNotFoundError,
                errors.IncorrectPassphraseError) as e:
            tkMessageBox.showerror(e.title, e.message)
        except errors.NymservNotFoundError as e:
            if tkMessageBox.askyesno(e.title, e.message + LINESEP +
                                     'Would you like to import it?'):
                KeyWindow(self.gui, self.client)
        except errors.NymNotFoundError as e:
            if tkMessageBox.askyesno(e.title, e.message + LINESEP +
                                     'Would you like to create it?'):
                self.start_session(address, passphrase, True)
        else:
            self.gui.start_session(creating_nym)


class ServersWindow(Tk.Tk, object):
    def __init__(self, gui, client):
        super(ServersWindow, self).__init__()

        self.gui = gui
        self.client = client

        self.title('Nym Servers')
        frame_servers = Tk.Frame(self)
        frame_servers.grid(sticky='w', padx=15, pady=15)

        # import default keys button
        button_import_default = Tk.Button(frame_servers,
                                          text='Import Default Keys',
                                          command=self.import_default_keys)
        button_import_default.grid(pady=(0, 10))

        # servers list box
        frame_list = Tk.LabelFrame(frame_servers, text='Nym Servers')
        frame_list.grid(sticky='we')
        self.list_servers = Tk.Listbox(frame_list, height=11, width=40)
        self.list_servers.grid(row=0, column=0, sticky='we')
        scrollbar_list = Tk.Scrollbar(frame_list, command=self.list_servers.yview)
        scrollbar_list.grid(row=0, column=1, sticky='nsew')
        self.list_servers['yscrollcommand'] = scrollbar_list.set
        self.list_servers.bind('<<ListboxSelect>>', self.toggle_servers_interface)

        buttons_row = frame_servers.grid_size()[1] + 1

        # new button
        button_new_servers = Tk.Button(frame_servers, text='New', command=lambda: KeyWindow(self.gui, self.client,
                                                                                            self))
        button_new_servers.grid(row=buttons_row, sticky='w', pady=(10, 0))

        # modify button
        self.button_modify_servers = Tk.Button(frame_servers, text='Modify',
                                               command=lambda: KeyWindow(self.gui, self.client, self,
                                                                         self.list_servers.get(
                                                                             self.list_servers.curselection())),
                                               state=Tk.DISABLED)
        self.button_modify_servers.grid(row=buttons_row, pady=(10, 0))

        # delete button
        self.button_delete_servers = Tk.Button(frame_servers, text='Delete',
                                               command=lambda: self.delete_key(self.list_servers.get(
                                                   self.list_servers.curselection())),
                                               state=Tk.DISABLED)
        self.button_delete_servers.grid(row=buttons_row, sticky='e', pady=(10, 0))

        self.update_servers_list()

    def toggle_servers_interface(self, event=None):
        if event:
            self.button_modify_servers.config(state=Tk.NORMAL)
            self.button_delete_servers.config(state=Tk.NORMAL)
        else:
            self.button_modify_servers.config(state=Tk.DISABLED)
            self.button_delete_servers.config(state=Tk.DISABLED)

    def update_servers_list(self):
        self.list_servers.delete(0, Tk.END)
        for s in self.client.retrieve_servers().keys():
            self.list_servers.insert(Tk.END, s)
        self.toggle_servers_interface()

    def import_default_keys(self):
        if tkMessageBox.askokcancel('Confirm', 'This will import public keys '
                                    'included with nymphemeral to the client '
                                    'keyring.'):
            self.client.import_default_keys()
            self.update_servers_list()

    def delete_key(self, server):
        if tkMessageBox.askyesno('Confirm', 'Are you sure you want to delete ' + server + "'s key?"):
            self.client.delete_key(server)
            self.update_servers_list()


class KeyWindow(Tk.Tk, object):
    def __init__(self, gui, client, parent=None, server=None):
        super(KeyWindow, self).__init__()

        self.gui = gui
        self.client = client
        self.parent = parent

        self.title('Public Key Manager')

        frame_key = Tk.Frame(self)
        frame_key.grid(sticky='w', padx=15, pady=15)

        # key text box
        key = ''
        if server:
            frame_list = Tk.LabelFrame(frame_key, text=server + "'s Public Key")
            key = self.client.gpg.export_keys(self.client.retrieve_servers()[server])
        else:
            frame_list = Tk.LabelFrame(frame_key, text='New Server Public Key')
        frame_list.grid(sticky='we')
        text_key = Tk.Text(frame_list, height=22, width=66)
        text_key.grid(row=0, column=0, sticky='we')
        scrollbar_text = Tk.Scrollbar(frame_list, command=text_key.yview)
        scrollbar_text.grid(row=0, column=1, sticky='nsew')
        text_key['yscrollcommand'] = scrollbar_text.set
        text_key.insert(Tk.INSERT, key)

        # save button
        button_save_key = Tk.Button(frame_key, text='Save',
                                    command=lambda: self.save_key(text_key.get(1.0, Tk.END), server))
        button_save_key.grid(pady=(10, 0))

        text_key.mark_set(Tk.INSERT, 1.0)
        text_key.focus_set()

    def save_key(self, key, server):
        self.client.save_key(key, server)
        if self.parent:
            self.parent.update_servers_list()
        self.destroy()


class MainWindow(Tk.Tk, object):
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
        self.title(self.gui.title)

        # frame inside root window
        frame_tab = Tk.Frame(self)
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

        self.notebook.pack(fill=Tk.BOTH, expand=True)

        # footer
        frame_footer = Tk.Frame(frame_tab)
        frame_footer.pack(fill=Tk.X, expand=True, padx=5, pady=5)

        frame_left = Tk.Frame(frame_footer)
        frame_left.pack(side=Tk.LEFT)
        frame_nym = Tk.Frame(frame_left)
        frame_nym.pack(fill=Tk.X, expand=True)
        self.label_nym = Tk.Label(frame_nym)
        self.label_nym.pack(side=Tk.LEFT)
        self.update_nym_info()
        if self.client.output_method == 'mixmaster':
            frame_chain = Tk.Frame(frame_left)
            frame_chain.pack(fill=Tk.X, expand=True)
            label_chain = Tk.Label(frame_chain, text=self.client.chain_info)
            label_chain.pack(side=Tk.LEFT)
        button_change_nym = Tk.Button(frame_footer, text='Change Nym', command=self.gui.end_session)
        button_change_nym.pack(side=Tk.RIGHT)

        # move window to the center
        self.update_idletasks()
        window_w, window_h = self.winfo_width(), self.winfo_height()
        screen_w, screen_h = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry('%dx%d+%d+%d' % (window_w, window_h, (screen_w - window_w) / 2, (screen_h - window_h) / 2))

    def update_nym_info(self):
        text_nym = self.client.nym_address
        exp = self.client.nym_expiration_date
        if exp:
            text_nym += ' (expiration: ' + exp + ')'
        self.label_nym.config(text=text_nym)

    def set_tab_state(self, tab, enabled):
        if enabled:
            state = Tk.NORMAL
        else:
            state = Tk.DISABLED
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


class CreationTab(Tk.Frame, object):
    def __init__(self, gui, client, parent):
        super(CreationTab, self).__init__(parent)

        self.gui = gui
        self.client = client

        frame_tab = Tk.Frame(self)
        frame_tab.grid(sticky='nswe', padx=15, pady=15)

        # name
        label_name = Tk.Label(frame_tab, text='Pseudonymous Name')
        label_name.grid(sticky=Tk.W)
        self.entry_name_create = Tk.Entry(frame_tab)
        self.entry_name_create.grid(sticky='we')

        # duration
        label_duration = Tk.Label(frame_tab, text='Duration')
        label_duration.grid(sticky=Tk.W, pady=(10, 0))
        self.entry_duration_create = Tk.Entry(frame_tab)
        self.entry_duration_create.grid(sticky='we')

        # ephemeral
        frame_ephemeral = Tk.Frame(frame_tab)
        frame_ephemeral.grid(sticky=Tk.EW, pady=(10, 0))
        label_ephemeral = Tk.Label(frame_ephemeral, text='Ephemeral Key')
        label_ephemeral.grid()
        var_gen_ephemeral = Tk.BooleanVar(value=True)
        self.check_gen_ephemeral = Tk.Checkbutton(
            frame_ephemeral,
            text='Auto-generate',
            variable=var_gen_ephemeral)
        self.check_gen_ephemeral.var = var_gen_ephemeral
        self.check_gen_ephemeral.grid(row='0', column='1')
        self.entry_ephemeral_create = Tk.Entry(frame_tab, state=Tk.DISABLED)
        self.entry_ephemeral_create.grid(sticky=Tk.EW)
        bind_checkbutton_and_entry(self.check_gen_ephemeral,
                                   self.entry_ephemeral_create)

        # hSub
        frame_hsub = Tk.Frame(frame_tab)
        frame_hsub.grid(sticky=Tk.EW, pady=(10, 0))
        label_hsub = Tk.Label(frame_hsub, text='hSub Passphrase')
        label_hsub.grid()
        var_gen_hsub = Tk.BooleanVar(value=True)
        self.check_gen_hsub = Tk.Checkbutton(frame_hsub,
                                             text='Auto-generate',
                                             variable=var_gen_hsub)
        self.check_gen_hsub.var = var_gen_hsub
        self.check_gen_hsub.grid(row='0', column='1')
        self.entry_hsub_create = Tk.Entry(frame_tab, state=Tk.DISABLED)
        self.entry_hsub_create.grid(sticky=Tk.EW)
        bind_checkbutton_and_entry(self.check_gen_hsub,
                                   self.entry_hsub_create)

        # create button
        self.button_create = Tk.Button(frame_tab,
                                       text='Create Nym',
                                       command=lambda: self.create(
                                           self.entry_name_create.get(),
                                           self.entry_duration_create.get(),
                                           self.entry_ephemeral_create.get(),
                                           self.entry_hsub_create.get())
                                       )
        self.button_create.grid(pady=(10, 0))

        # message box
        frame_text = Tk.LabelFrame(frame_tab, text='Nym Creation Headers and Configuration')
        frame_text.grid(sticky='we', pady=10)
        self.text_create = Tk.Text(frame_text, height=25)
        self.text_create.grid(row=0, column=0)
        scrollbar = Tk.Scrollbar(frame_text, command=self.text_create.yview)
        scrollbar.grid(row=0, column=1, sticky='ns')
        self.text_create['yscrollcommand'] = scrollbar.set
        self.text_create.insert(Tk.INSERT,
                                'Key generation may take a long time after '
                                'you click the "Create Nym" button.' +
                                LINESEP + 'Be prepared to wait...')

        self.entry_name_create.focus_set()

    def set_interface(self, enabled):
        if enabled:
            state = Tk.NORMAL
        else:
            state = Tk.DISABLED
        self.check_gen_ephemeral.config(state=state)
        self.entry_ephemeral_create.config(state=state)
        self.check_gen_hsub.config(state=state)
        self.entry_hsub_create.config(state=state)
        self.entry_name_create.config(state=state)
        self.entry_duration_create.config(state=state)
        self.button_create.config(state=state)

    def create(self, name, duration, ephemeral, hsub):
        if self.check_gen_ephemeral.var.get():
            ephemeral = None
        if self.check_gen_hsub.var.get():
            hsub = None
        try:
            success, info, ciphertext = self.client.send_create(name,
                                                                duration,
                                                                ephemeral,
                                                                hsub)
        except errors.NymphemeralError as e:
            tkMessageBox.showerror(e.title, e.message)
        else:
            write_on_text(self.text_create, [info, ciphertext])
            if success:
                self.gui.window_main.update_nym_info()
                self.set_interface(False)
                self.gui.window_main.set_creation_interface(False)


class InboxTab(Tk.Frame, object):
    def __init__(self, gui, client, tab_send, tab_unread, parent):
        super(InboxTab, self).__init__(parent)

        self.gui = gui
        self.client = client
        self.tab_send = tab_send
        self.tab_unread = tab_unread
        self.messages = None
        self.current_message_index = None

        frame_tab = Tk.Frame(self)
        frame_tab.grid(sticky='nswe', padx=15, pady=15)

        frame_retrieve = Tk.Frame(frame_tab)
        frame_retrieve.grid(sticky='w', pady=(0, 10))

        # retrieve button
        self.button_aampy_inbox = Tk.Button(frame_retrieve, width=14, text='Retrieve Messages',
                                            command=self.start_retrieving_messages)
        self.button_aampy_inbox.grid(row=0, sticky='w')

        # progress bar
        self.progress_bar_inbox = ttk.Progressbar(frame_retrieve, mode='indeterminate', length=427)

        # messages list box
        frame_list = Tk.LabelFrame(frame_tab, text='Messages')
        frame_list.grid(sticky='we')
        self.list_messages_inbox = Tk.Listbox(frame_list, height=11, width=70)
        self.list_messages_inbox.grid(row=0, column=0, sticky='we')
        scrollbar_list = Tk.Scrollbar(frame_list, command=self.list_messages_inbox.yview)
        scrollbar_list.grid(row=0, column=1, sticky='nsew')
        self.list_messages_inbox['yscrollcommand'] = scrollbar_list.set
        self.list_messages_inbox.bind('<<ListboxSelect>>', self.select_message)

        # message contents
        frame_content = Tk.Frame(frame_tab)
        frame_content.grid(pady=10, sticky='we')
        notebook = ttk.Notebook(frame_content)
        notebook.pack()

        frame_body = Tk.Frame(notebook)
        frame_headers = Tk.Frame(notebook)

        # body tab
        self.text_body_inbox = Tk.Text(frame_body, height=22, state=Tk.DISABLED)
        scrollbar_body = Tk.Scrollbar(frame_body, command=self.text_body_inbox.yview)
        scrollbar_body.grid(row=0, column=1, sticky='nsew')
        self.text_body_inbox['yscrollcommand'] = scrollbar_body.set
        self.text_body_inbox.grid(row=0, column=0, sticky='we')

        # headers tab
        self.text_headers_inbox = Tk.Text(frame_headers, height=22, state=Tk.DISABLED)
        scrollbar_headers = Tk.Scrollbar(frame_headers, command=self.text_headers_inbox.yview)
        scrollbar_headers.grid(row=0, column=1, sticky='nsew')
        self.text_headers_inbox['yscrollcommand'] = scrollbar_headers.set
        self.text_headers_inbox.grid(row=0, column=0, sticky='we')

        notebook.add(frame_body, text='Body')
        notebook.add(frame_headers, text='Headers')
        notebook.pack(fill=Tk.BOTH, expand=True)

        buttons_row = frame_tab.grid_size()[1] + 1

        # save/delete button
        self.button_save_del_inbox = Tk.Button(frame_tab, text='Save to Disk', command=self.save_and_update_interface)
        self.button_save_del_inbox.grid(row=buttons_row, sticky='w', pady=(10, 0))

        # reply button
        self.button_reply_inbox = Tk.Button(frame_tab, text='Reply Message', command=self.reply_message)
        self.button_reply_inbox.grid(row=buttons_row, sticky='e', pady=(10, 0))

        # notification label
        self.label_save_del_inbox = Tk.Label(frame_tab)
        self.label_save_del_inbox.grid(row=buttons_row, pady=(10, 0))

        self.load_messages()

    def update_messages_list(self):
        self.toggle_interface(False)
        self.list_messages_inbox.delete(0, Tk.END)
        for m in self.messages:
            self.list_messages_inbox.insert(Tk.END, m.title)
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
        if self.client.aampy.is_running is False:
            self.gui.window_main.id_after = None
            if self.client.aampy.server_found:
                self.load_messages()
            else:
                self.toggle_interface(False)
                tkMessageBox.showerror('Socket Error', 'The news server cannot be found!')
        else:
            if self.client.aampy.progress_ratio is not None:
                self.progress_bar_inbox.stop()
                self.progress_bar_inbox.config(mode='determinate', value=int(self.client.aampy.progress_ratio * 100))
            self.gui.window_main.id_after = self.gui.window_main.after(1000, lambda: self.wait_for_retrieval())

    def toggle_interface(self, retrieving_messages):
        self.button_save_del_inbox.config(state=Tk.DISABLED)
        self.button_reply_inbox.config(state=Tk.DISABLED)
        if retrieving_messages:
            self.list_messages_inbox.config(state=Tk.DISABLED)
            self.progress_bar_inbox.grid(row=0, column=1, sticky='nswe', padx=(15, 0))
            self.progress_bar_inbox.config(mode='indeterminate')
            self.progress_bar_inbox.start(25)
            self.button_aampy_inbox.config(text='Stop', command=self.stop_retrieving_messages)
        else:
            self.list_messages_inbox.config(state=Tk.NORMAL)
            self.progress_bar_inbox.stop()
            self.progress_bar_inbox.grid_forget()
            self.button_aampy_inbox.config(text='Retrieve Messages', command=self.start_retrieving_messages)

    def decrypt_e2ee_message(self, msg):
        pgp_message = search_pgp_message(msg.content)
        if pgp_message:
            if self.client.use_agent:
                return self.client.decrypt_e2ee_message(msg)
            else:
                keyids = retrieve_keyids(pgp_message)
                keys = []
                if keyids:
                    for k in keyids:
                        try:
                            keys.append(retrieve_key(self.client.gpg, k))
                        except errors.KeyNotFoundError:
                            pass
                if keys:
                    prompt = 'Message encrypted to:' + LINESEP
                    for k in keys:
                        prompt += format_key_info(k)
                else:
                    prompt = ('The key ID which the message was encrypted to '
                              'was removed or is not in the keyring.' +
                              LINESEP)
                prompt += 'Provide a passphrase to attempt to decrypt it:'
                passphrase = tkSimpleDialog.askstring('End-to-End Encrypted Message',
                                                      prompt,
                                                      parent=self,
                                                      show='*')
                if passphrase is None:
                    return msg
                else:
                    return self.client.decrypt_e2ee_message(msg, passphrase)
        else:
            return msg

    def select_message(self, event):
        if len(self.messages) and not self.client.aampy.is_running:
            index = int(event.widget.curselection()[0])
            self.current_message_index = index

            if self.messages[index].is_unread:
                self.button_save_del_inbox.config(state=Tk.DISABLED)
                self.button_reply_inbox.config(state=Tk.DISABLED)

                try:
                    self.messages[index] = self.client.decrypt_ephemeral_message(self.messages[index])
                except errors.UndecipherableMessageError as e:
                    tkMessageBox.showerror(e.title, e.message)
                    self.messages.pop(index)
                    self.current_message_index = None
                    self.update_messages_list()
                else:
                    # Check for and decrypt an end-to-end encryption layer
                    try:
                        self.messages[index] = self.decrypt_e2ee_message(self.messages[index])
                    except errors.UndecipherableMessageError:
                        pass

                    self.update_messages_list()
                    self.display_message(self.messages[index])
            else:
                self.display_message(self.messages[index])

    def display_message(self, msg):
        write_on_text(self.text_headers_inbox, [msg.headers])
        write_on_text(self.text_body_inbox, [msg.content])
        if os.path.exists(msg.identifier):
            self.toggle_save_del_button(False)
        else:
            self.toggle_save_del_button(True)
        self.button_save_del_inbox.config(state=Tk.NORMAL)
        self.button_reply_inbox.config(state=Tk.NORMAL)

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


class SendTab(Tk.Frame, object):
    def __init__(self, gui, client, parent):
        super(SendTab, self).__init__(parent)

        self.gui = gui
        self.client = client
        self.var_throw_keyids = Tk.BooleanVar()

        frame_tab = Tk.Frame(self)
        frame_tab.grid(sticky='nswe', padx=15, pady=15)

        # target
        label_target = Tk.Label(frame_tab, text='Target Email Address')
        label_target.grid(sticky=Tk.W)
        self.entry_target_send = Tk.Entry(frame_tab)
        self.entry_target_send.grid(sticky='we')

        # subject
        label_subject = Tk.Label(frame_tab, text='Subject')
        label_subject.grid(sticky=Tk.W, pady=(10, 0))
        self.entry_subject_send = Tk.Entry(frame_tab)
        self.entry_subject_send.grid(sticky='we')

        # header box
        frame_header = Tk.LabelFrame(frame_tab, text='Headers (Optional)')
        frame_header.grid(pady=(10, 0))
        self.text_header = Tk.Text(frame_header, height=4)
        self.text_header.grid(row=0, column=0)
        scrollbar_header = Tk.Scrollbar(frame_header, command=self.text_header.yview)
        scrollbar_header.grid(row=0, column=1, sticky='ns')
        self.text_header['yscrollcommand'] = scrollbar_header.set

        # body box
        frame_body = Tk.LabelFrame(frame_tab, text='Message')
        frame_body.grid(pady=(10, 0))
        self.text_body = Tk.Text(frame_body, height=20)
        self.text_body.grid(row=0, column=0)
        scrollbar_body = Tk.Scrollbar(frame_body, command=self.text_body.yview)
        scrollbar_body.grid(row=0, column=1, sticky='ns')
        self.text_body['yscrollcommand'] = scrollbar_body.set

        # e2ee
        frame_e2ee = Tk.LabelFrame(frame_tab, text='End-to-End Encryption (Recommended)')
        frame_e2ee.grid(sticky='we', ipady=5, pady=(10, 0))

        # e2ee target
        label_e2ee_target = Tk.Label(frame_e2ee, text='Target')
        label_e2ee_target.grid(row=0, sticky=Tk.W, padx=12)
        self.entry_e2ee_target_send = Tk.Entry(frame_e2ee, width=33)
        self.entry_e2ee_target_send.grid(row=1, sticky='w', padx=(12, 284))

        # e2ee signer
        label_e2ee_signer = Tk.Label(frame_e2ee, text='Signer')
        label_e2ee_signer.grid(row=0, sticky=Tk.E)
        self.entry_e2ee_signer_send = Tk.Entry(frame_e2ee, width=33)
        self.entry_e2ee_signer_send.grid(row=1, sticky='e')

        # e2ee tip
        label_tip = Tk.Label(frame_e2ee, text='(UIDs or Fingerprints)')
        label_tip.grid(row=0)

        # throw key IDs checkbox
        check_throw_keyids = Tk.Checkbutton(frame_e2ee, text='Throw Key IDs', variable=self.var_throw_keyids)
        check_throw_keyids.grid(sticky='w', padx=(5, 0))

        # send button
        button_send = Tk.Button(frame_tab, text='Send',
                                command=lambda: self.send_message(self.entry_target_send.get(),
                                                                  self.entry_subject_send.get(),
                                                                  self.text_header.get(1.0, Tk.END),
                                                                  self.text_body.get(1.0, Tk.END),
                                                                  self.entry_e2ee_target_send.get(),
                                                                  self.entry_e2ee_signer_send.get()))
        button_send.grid(pady=(10, 0))

    def compose_message(self, msg):
        self.entry_target_send.delete(0, Tk.END)
        if msg.sender:
            self.entry_target_send.insert(0, msg.sender.lower())
        self.entry_subject_send.delete(0, Tk.END)
        if msg.subject:
            self.entry_subject_send.insert(0, msg.subject)
            if not msg.subject.startswith('Re: '):
                self.entry_subject_send.insert(0, 'Re: ')
        content = LINESEP*2
        for line in msg.content.splitlines():
            content += '> ' + line + LINESEP
        if msg.id:
            header = 'In-Reply-To: ' + msg.id
            write_on_text(self.text_header, [header])
        write_on_text(self.text_body, [content])
        cursor_position = 1.0
        self.text_body.mark_set(Tk.INSERT, cursor_position)
        self.gui.window_main.select_tab(self)
        self.text_body.focus_set()

    def send_message(self, target_address, subject, headers, body,
                     e2ee_target='', e2ee_signer=''):
        e2ee_signer = e2ee_signer.strip()
        passphrase = None
        throw_keyids = bool(self.var_throw_keyids.get())
        try:
            # if signing, nymphemeral's own dialog will prompt for a passphrase
            # in case the user chose not to use the GPG agent
            if e2ee_signer and not self.client.use_agent:
                e2ee_signer_key = retrieve_key(self.client.gpg, e2ee_signer)
                prompt = (
                    'Signing with:' + LINESEP +
                    format_key_info(e2ee_signer_key) +
                    'Provide a passphrase to unlock the secret key:'
                )
                passphrase = tkSimpleDialog.askstring(
                    title='Passphrase Required',
                    prompt=prompt,
                    parent=self,
                    show='*'
                )
                if passphrase is None:
                    # the user has canceled
                    return
            success, info, ciphertext = self.client.send_message(
                target_address,
                body,
                subject,
                headers,
                e2ee_target,
                e2ee_signer,
                passphrase,
                throw_keyids
            )
        except errors.NymphemeralError as e:
            tkMessageBox.showerror(e.title, e.message)
        else:
            write_on_text(self.text_body, [info, ciphertext])


class ConfigTab(Tk.Frame, object):
    def __init__(self, gui, client, parent):
        super(ConfigTab, self).__init__(parent)

        self.gui = gui
        self.client = client

        frame_tab = Tk.Frame(self)
        frame_tab.grid(sticky='nswe', padx=15, pady=15)

        # name
        label_name = Tk.Label(frame_tab, text='Pseudonymous Name')
        label_name.grid(sticky=Tk.W)
        self.entry_name_config = Tk.Entry(frame_tab)
        self.entry_name_config.grid(sticky='we')

        # ephemeral
        frame_ephemeral = Tk.Frame(frame_tab)
        frame_ephemeral.grid(sticky=Tk.EW, pady=(10, 0))
        label_ephemeral = Tk.Label(frame_ephemeral, text='Ephemeral Key')
        label_ephemeral.grid()
        var_gen_ephemeral = Tk.BooleanVar()
        self.check_gen_ephemeral = Tk.Checkbutton(frame_ephemeral,
                                                  text='Auto-generate',
                                                  variable=var_gen_ephemeral)
        self.check_gen_ephemeral.var = var_gen_ephemeral
        self.check_gen_ephemeral.grid(row='0', column='1')
        self.entry_ephemeral_config = Tk.Entry(frame_tab)
        self.entry_ephemeral_config.grid(sticky=Tk.EW)
        bind_checkbutton_and_entry(self.check_gen_ephemeral,
                                   self.entry_ephemeral_config)

        # hSub
        frame_hsub = Tk.Frame(frame_tab)
        frame_hsub.grid(sticky=Tk.EW, pady=(10, 0))
        label_hsub = Tk.Label(frame_hsub, text='hSub Key')
        label_hsub.grid()
        var_gen_hsub = Tk.BooleanVar()
        self.check_gen_hsub = Tk.Checkbutton(frame_hsub,
                                             text='Auto-generate',
                                             variable=var_gen_hsub)
        self.check_gen_hsub.var = var_gen_hsub
        self.check_gen_hsub.grid(row='0', column='1')
        self.entry_hsub_config = Tk.Entry(frame_tab)
        self.entry_hsub_config.grid(sticky=Tk.EW)
        bind_checkbutton_and_entry(self.check_gen_hsub,
                                   self.entry_hsub_config)

        buttons_row = frame_tab.grid_size()[1] + 1

        # config button
        self.button_config = Tk.Button(frame_tab, text='Configure',
                                       command=lambda: self.send_config(self.entry_ephemeral_config.get().strip(),
                                                                        self.entry_hsub_config.get().strip(),
                                                                        self.entry_name_config.get().strip()))
        self.button_config.grid(row=buttons_row, sticky='w', pady=(10, 0))

        # delete button
        self.button_delete_config = Tk.Button(frame_tab, text='Delete Nym', command=self.send_delete)
        self.button_delete_config.grid(row=buttons_row, sticky='e', pady=(10, 0))

        # message box
        frame_text = Tk.LabelFrame(frame_tab, text='Nym Configuration Headers')
        frame_text.grid(sticky='we', pady=(10, 0))
        self.text_config = Tk.Text(frame_text, height=29)
        self.text_config.grid(row=0, column=0)
        scrollbar = Tk.Scrollbar(frame_text, command=self.text_config.yview)
        scrollbar.grid(row=0, column=1, sticky='ns')
        self.text_config['yscrollcommand'] = scrollbar.set

    def set_deleted_interface(self):
        self.gui.window_main.set_all_tabs_state(False, [self])
        self.check_gen_ephemeral.config(state=Tk.DISABLED)
        self.entry_ephemeral_config.config(state=Tk.DISABLED)
        self.check_gen_hsub.config(state=Tk.DISABLED)
        self.entry_hsub_config.config(state=Tk.DISABLED)
        self.entry_name_config.config(state=Tk.DISABLED)
        self.button_config.config(state=Tk.DISABLED)
        self.button_delete_config.config(state=Tk.DISABLED)

    def send_config(self, ephemeral, hsub, name):
        if tkMessageBox.askyesno('Confirm',
                                 'Are you sure you want to reconfigure the '
                                 'nym?'):
            try:
                success, info, ciphertext = self.client.send_config(
                    ephemeral,
                    hsub,
                    name,
                    gen_ephemeral=self.check_gen_ephemeral.var.get(),
                    gen_hsub=self.check_gen_hsub.var.get())
            except errors.EmptyChangesError as e:
                tkMessageBox.showerror(e.title, e.message)
            else:
                write_on_text(self.text_config, [info, ciphertext])

    def send_delete(self):
        if tkMessageBox.askyesno('Confirm', 'Are you sure you want to delete the nym?'):
            success, info, ciphertext = self.client.send_delete()
            write_on_text(self.text_config, [info, ciphertext])
            if success:
                self.set_deleted_interface()


class UnreadCounterTab(Tk.Frame, object):
    def __init__(self, gui, client, parent):
        super(UnreadCounterTab, self).__init__(parent)

        self.gui = gui
        self.client = client

        frame_tab = Tk.Frame(self)
        frame_tab.grid(sticky='nswe', padx=15, pady=15)

        frame_retrieve = Tk.Frame(frame_tab)
        frame_retrieve.grid(sticky='w')

        frame_list = Tk.LabelFrame(frame_tab, text='Nyms With Unread Messages')
        frame_list.grid(sticky='we')
        self.list_unread = Tk.Listbox(frame_list, height=39, width=70)
        self.list_unread.grid(row=0, column=0, sticky='we')
        scrollbar_list = Tk.Scrollbar(frame_list, command=self.list_unread.yview)
        scrollbar_list.grid(row=0, column=1, sticky='nsew')
        self.list_unread['yscrollcommand'] = scrollbar_list.set

        self.update_unread_counter()

    def update_unread_counter(self):
        counter = sorted(self.client.count_unread_messages().items(), key=operator.itemgetter(0))
        self.list_unread.delete(0, Tk.END)
        if counter:
            for nym, count in counter:
                self.list_unread.insert(Tk.END, nym + '(' + str(count) + ')')
        else:
            self.list_unread.insert(Tk.END, 'No messages found')


def main():
    Gui().window_login.mainloop()


if __name__ == '__main__':
    sys.exit(main())
