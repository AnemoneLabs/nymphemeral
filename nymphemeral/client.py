import os
import re
import subprocess
import hashlib
import sys
import shutil
import threading
import ConfigParser
import email
import itertools
from binascii import b2a_base64, a2b_base64
import Tkinter

import gnupg
from passlib.utils.pbkdf2 import pbkdf2
import time

from pyaxo import Axolotl
import aampy
import message
import errors
from nym import Nym


BASE_FILES_PATH = '/usr/share/nymphemeral'
USER_PATH = os.path.expanduser('~')
NYMPHEMERAL_PATH = USER_PATH + '/.config/nymphemeral'
CONFIG_FILE = NYMPHEMERAL_PATH + '/nymphemeral.cfg'
OUTPUT_METHOD = {
    'mixmaster': 1,
    'sendmail': 2,
    'manual': 3,
}


def files_in_path(path):
    return [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]


def create_directory(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)


def create_dictionary(string):
    return dict(t.split() for t in string.strip().split('\n'))


def search_block(data, beginning, end):
    """
    Return the first block found in the format:
        beginning
        <content>
        end
    Return None if beginning or end are not found
    """

    msg = ''
    for line in data.split('\n'):
        if msg:
            msg += line + '\n'
            if line == end:
                return msg
        elif line == beginning:
            msg = line + '\n'
    return None


def search_pgp_message(data):
    """Return the first PGP message found, return None otherwise"""

    return search_block(data, '-----BEGIN PGP MESSAGE-----', '-----END PGP MESSAGE-----')


def read_data(identifier):
    try:
        with open(identifier, 'r') as f:
            return f.read()
    except IOError:
        print 'Error while reading ' + identifier
    return None


def save_data(data, identifier):
    try:
        with open(identifier, 'w') as f:
            f.write(data)
            return True
    except IOError:
        print 'Error while writing to ' + identifier
    return False


def new_gpg(paths):
    keyring = []
    for r in list(itertools.product(paths, ['/pubring.gpg'])):
        keyring.append(''.join(r))
    secret_keyring = []
    for r in list(itertools.product(paths, ['/secring.gpg'])):
        secret_keyring.append(''.join(r))
    binary = '/usr/bin/gpg'
    gpg = gnupg.GPG(binary,
                    paths[0],
                    keyring=keyring,
                    secret_keyring=secret_keyring,
                    options=['--personal-digest-preferences=sha256',
                             '--s2k-digest-algo=sha256'])
    gpg.encoding = 'latin-1'
    return gpg


def generate_key(gpg, name, address, passphrase, duration):
    input_data = gpg.gen_key_input(key_type='RSA', key_length='4096', subkey_type='RSA',
                                   subkey_length='4096', key_usage='sign,auth',
                                   subkey_usage='encrypt', expire_date=duration,
                                   passphrase=passphrase, name_real=name,
                                   name_comment='', name_email=address)
    fingerprint = gpg.gen_key(input_data).fingerprint
    return gpg.export_keys(keyids=address), fingerprint


def retrieve_key(gpg, query):
    """Return the ONLY key found for the query specified"""

    query = query.lower()
    results = []
    keys = gpg.list_keys()

    for k in keys:
        if k['keyid'].lower().endswith(query) or k['fingerprint'].lower().endswith(query):
            results.append(k)
        else:
            for sub in k['subkeys']:
                if sub[0].lower().endswith(query):
                    results.append(k)
                    break
            else:
                for uid in k['uids']:
                    if re.search(r'\b' + query + r'\b', uid, flags=re.IGNORECASE):
                        results.append(k)
                        break
    if results:
        for r in results[1:]:
            if r['fingerprint'] != results[0]['fingerprint']:
                raise errors.AmbiguousUidError(query)
        return results[0]
    else:
        raise errors.KeyNotFoundError(query)


def retrieve_fingerprint(gpg, query):
    """Return the ONLY fingerprint found for the query specified"""

    return retrieve_key(gpg, query)['fingerprint']


def format_key_info(key):
    """
    Process a dictionary with key information and return it in a format similar to GPG's

    key should be a dictionary in the same format as the one returned by gpg.list_keys()

    The resulting string will be in the format:
        Username <user@domain>
        4096-bit key, ID 31415926, expires 2015-03-14
    """

    info = ''
    for uid in key['uids']:
        info += uid + '\n'
    info += key['length'] + '-bit key' \
        + ', ID ' + key['keyid'][-8:] \
        + ', expires ' + time.strftime('%Y-%m-%d', time.gmtime(float(key['expires']))) \
        + '\n'
    return info


def retrieve_keyids(msg):
    """
    Return key IDs used to encrypt a PGP message

    Expects to get something like the following format from gpg --list-packets:
        :pubkey enc packet: version 3, algo 1, keyid 4096409640964096
            data: [4096 bits]
        :pubkey enc packet: version 3, algo 1, keyid 0248163264128256
            data: [4096 bits]
        :encrypted data packet:
            length: unknown
            mdc_method: 2
        gpg: encrypted with RSA key, ID 64128256
        gpg: encrypted with RSA key, ID 40964096
    """

    keyids = []
    p = subprocess.Popen(['gpg', '--no-tty', '--list-packets', '--list-only'],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE)
    out, err = p.communicate(msg)
    for line in out.splitlines():
        result = re.match(r':pubkey.*\bkeyid (\w+)\b.*', line)
        if result:
            # append valid key IDs (not thrown away)
            if not re.match('^0*$', result.group(1)):
                keyids.append(result.group(1))
    return keyids


def encrypt_data(gpg, data, recipients, fingerprint, passphrase):
    result = gpg.encrypt(data,
                         recipients,
                         sign=fingerprint,
                         passphrase=passphrase,
                         always_trust=True)
    if result.ok:
        return str(result)
    else:
        return None


def decrypt_data(gpg, data, passphrase):
    result = gpg.decrypt(data,
                         passphrase=passphrase,
                         always_trust=True)
    if result.ok:
        return str(result)
    else:
        return None


def copy_to_clipboard(data):
    t = Tkinter.Tk()
    t.withdraw()
    t.clipboard_clear()
    t.clipboard_append(data)
    t.destroy()


def generate_db(directory, fingerprint, mkey, passphrase):
    mkey = hashlib.sha256(mkey).digest()
    dbname = directory + '/generic.db'
    a = Axolotl('b', dbname, None)
    a.loadState('b', 'a')
    a.dbname = directory + '/' + fingerprint + '.db'
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


class Client:
    def __init__(self):
        self.cfg = ConfigParser.ConfigParser()

        self.directory_base = None
        self.directory_db = None
        self.directory_read_messages = None
        self.directory_unread_messages = None
        self.directory_gpg = None
        self.file_hsub = None
        self.file_encrypted_hsub = None
        self.is_debugging = None
        self.output_method = None
        self.file_mix_binary = None
        self.file_mix_cfg = None
        self.check_base_files()

        # Local keyring, to communicate with the server
        self.gpg = new_gpg([self.directory_base])

        # User keyring, to communicate with other users (end-to-end)
        self.user_gpg = new_gpg([self.directory_gpg, self.directory_base])

        self.axolotl = None
        self.nym = None
        self.hsubs = {}

        # attributes to handle aampy (to retrieve new messages) using threads
        self.aampy = self.initialize_aampy()
        self.thread_aampy = None
        self.thread_aampy_wait = None

        self.chain = self.retrieve_mix_chain()

    def debug(self, info):
        if self.is_debugging:
            print info

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

    def load_configs(self):
        try:
            # load default configs
            self.cfg.add_section('gpg')
            self.cfg.set('gpg', 'base_folder', USER_PATH + '/.gnupg')
            self.cfg.add_section('main')
            self.cfg.set('main', 'base_folder', NYMPHEMERAL_PATH)
            self.cfg.set('main', 'db_folder', '%(base_folder)s/db')
            self.cfg.set('main', 'messages_folder', '%(base_folder)s/messages')
            self.cfg.set('main', 'read_folder', '%(messages_folder)s/read')
            self.cfg.set('main', 'unread_folder', '%(messages_folder)s/unread')
            self.cfg.set('main', 'hsub_file', '%(base_folder)s/hsubs.txt')
            self.cfg.set('main', 'encrypted_hsub_file', '%(base_folder)s/encrypted_hsubs.txt')
            self.cfg.set('main', 'debug_switch', 'False')
            self.cfg.set('main', 'output_method', 'manual')
            self.cfg.add_section('mixmaster')
            self.cfg.set('mixmaster', 'base_folder', USER_PATH + '/Mix')
            self.cfg.set('mixmaster', 'binary', '%(base_folder)s/mixmaster')
            self.cfg.set('mixmaster', 'cfg', '%(base_folder)s/mix.cfg')
            self.cfg.add_section('newsgroup')
            self.cfg.set('newsgroup', 'base_folder', NYMPHEMERAL_PATH)
            self.cfg.set('newsgroup', 'group', 'alt.anonymous.messages')
            self.cfg.set('newsgroup', 'server', 'localhost')
            self.cfg.set('newsgroup', 'port', '119')
            self.cfg.set('newsgroup', 'newnews', '%(base_folder)s/.newnews')

            # parse existing configs in case new versions modify them
            # or the user modifies the file inappropriately
            if os.path.exists(CONFIG_FILE):
                saved_cfg = ConfigParser.ConfigParser()
                saved_cfg.read(CONFIG_FILE)
                for section in saved_cfg.sections():
                    try:
                        for option in self.cfg.options(section):
                            try:
                                self.cfg.set(section, option, saved_cfg.get(section, option))
                            except:
                                pass
                    except:
                        pass
            else:
                create_directory(NYMPHEMERAL_PATH)
            self.save_configs()

            self.directory_base = self.cfg.get('main', 'base_folder')
            self.directory_db = self.cfg.get('main', 'db_folder')
            self.directory_read_messages = self.cfg.get('main', 'read_folder')
            self.directory_unread_messages = self.cfg.get('main', 'unread_folder')
            self.directory_gpg = self.cfg.get('gpg', 'base_folder')
            self.file_hsub = self.cfg.get('main', 'hsub_file')
            self.file_encrypted_hsub = self.cfg.get('main', 'encrypted_hsub_file')
            self.is_debugging = self.cfg.getboolean('main', 'debug_switch')
            self.output_method = self.cfg.get('main', 'output_method')
            self.file_mix_binary = self.cfg.get('mixmaster', 'binary')
            self.file_mix_cfg = self.cfg.get('mixmaster', 'cfg')
        except IOError:
            print 'Error while opening ' + str(CONFIG_FILE).split('/')[-1]
            raise

    def save_configs(self):
        with open(CONFIG_FILE, 'w') as config_file:
            self.cfg.write(config_file)

    def update_configs(self):
        self.cfg.set('main', 'output_method', self.output_method)

    def initialize_aampy(self):
        group = self.cfg.get('newsgroup', 'group')
        server = self.cfg.get('newsgroup', 'server')
        port = self.cfg.get('newsgroup', 'port')
        newnews = self.cfg.get('newsgroup', 'newnews')
        return aampy.AAMpy(self.directory_base, group, server, port, newnews, self.is_debugging)

    def retrieve_mix_chain(self):
        chain = None
        try:
            with open(self.file_mix_cfg, 'r') as config:
                lines = config.readlines()
                for line in lines:
                    s = re.match('(CHAIN )(.*)', line)
                    if s:
                        chain = 'Mix Chain: ' + s.group(2)
                        break
        except IOError:
            self.debug('Error while manipulating ' + self.file_mix_cfg.split('/')[-1])
        return chain

    def save_key(self, key, server=None):
        # also used to update an identity
        if server:
            self.gpg.delete_keys(self.retrieve_servers()[server])
        return self.gpg.import_keys(key)

    def delete_key(self, server):
        return self.gpg.delete_keys(self.retrieve_servers()[server])

    def retrieve_servers(self):
        servers = {}
        keys = self.gpg.list_keys()
        for item in keys:
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

    def retrieve_nyms(self):
        nyms = []
        keys = self.gpg.list_keys()
        for item in keys:
            if len(item['uids']) == 1:
                search = re.search('(?<=<).*(?=>)', item['uids'][0])
                if search:
                    address = search.group()
                    nym = Nym(address,
                              fingerprint=item['fingerprint'])
                    nyms.append(nym)
        return nyms

    def start_session(self, nym, output_method='manual', creating_nym=False):
        if nym.server not in self.retrieve_servers():
            raise errors.NymservNotFoundError(nym.server)
        result = filter(lambda n: n.address == nym.address, self.retrieve_nyms())
        if not result:
            if not creating_nym:
                raise errors.NymNotFoundError(nym.address)
        else:
            nym.fingerprint = result[0].fingerprint
            if not nym.fingerprint:
                raise errors.FingerprintNotFoundError(nym.address)
            db_name = self.directory_db + '/' + nym.fingerprint + '.db'
            try:
                # workaround to suppress prints by pyaxo
                sys.stdout = open(os.devnull, 'w')
                self.axolotl = Axolotl(nym.fingerprint, db_name, nym.passphrase)
                sys.stdout = sys.__stdout__
            except SystemExit:
                sys.stdout = sys.__stdout__
                raise errors.IncorrectPassphraseError()
        self.nym = nym
        self.hsubs = self.retrieve_hsubs()
        if not creating_nym:
            self.nym.hsub = self.hsubs[nym.address]
        self.update_output_method(output_method)

    def end_session(self):
        self.axolotl = None
        self.nym = None
        self.hsubs = {}

    def update_output_method(self, method):
        if method != self.output_method:
            self.output_method = method
            self.update_configs()
            self.save_configs()

    def decrypt_hsubs_file(self):
        if os.path.exists(self.file_encrypted_hsub):
            encrypted_data = read_data(self.file_encrypted_hsub)
            return decrypt_data(self.gpg, encrypted_data, self.nym.passphrase)
        else:
            self.debug('Decryption of ' + self.file_encrypted_hsub + ' failed. It does not exist')
        return None

    def save_hsubs(self, hsubs):
        output_file = self.file_hsub
        data = ''
        for key, item in hsubs.iteritems():
            data += key + ' ' + str(item) + '\n'
        # check if the nym has access or can create the encrypted hSub passphrases file
        if self.nym.fingerprint and (not os.path.exists(self.file_encrypted_hsub) or self.decrypt_hsubs_file()):
            nyms = self.retrieve_nyms()
            recipients = []
            for n in nyms:
                recipients.append(n.address)
            result = encrypt_data(self.gpg, data, recipients, self.nym.fingerprint, self.nym.passphrase)
            if result:
                output_file = self.file_encrypted_hsub
                data = result
        if save_data(data, output_file):
            if output_file == self.file_encrypted_hsub:
                if os.path.exists(self.file_hsub):
                    os.unlink(self.file_hsub)
                self.debug('The hsubs were encrypted and saved to ' + self.file_encrypted_hsub)
            return True
        else:
            return False

    def add_hsub(self, nym):
        self.hsubs[nym.address] = nym.hsub
        return self.save_hsubs(self.hsubs)

    def delete_hsub(self, nym):
        del self.hsubs[nym.address]
        # check if there are no hSub passphrases anymore
        if not self.hsubs or len(self.hsubs) == 1 and 'time' in self.hsubs:
            if self.decrypt_hsubs_file():
                hsub_file = self.file_encrypted_hsub
            else:
                hsub_file = self.file_hsub
            try:
                os.unlink(hsub_file)
            except IOError:
                print 'Error while manipulating ' + hsub_file.split('/')[-1]
                return False
        else:
            return self.save_hsubs(self.hsubs)
        return True

    def retrieve_hsubs(self):
        hsubs = {}
        encrypt_hsubs = False

        if os.path.exists(self.file_hsub):
            hsubs = create_dictionary(read_data(self.file_hsub))

        if os.path.exists(self.file_encrypted_hsub):
            decrypted_data = self.decrypt_hsubs_file()
            if decrypted_data:
                decrypted_hsubs = create_dictionary(decrypted_data)
                # check if there are unencrypted hSub passphrases
                if hsubs:
                    encrypt_hsubs = True
                    # merge hSub passphrases and save the "older" time to ensure messages are not skipped
                    try:
                        if hsubs['time'] < decrypted_hsubs['time']:
                            hsubs = dict(decrypted_hsubs.items() + hsubs.items())
                        else:
                            hsubs = dict(hsubs.items() + decrypted_hsubs.items())
                    except KeyError:
                        hsubs = dict(hsubs.items() + decrypted_hsubs.items())
                else:
                    hsubs = decrypted_hsubs
        else:
            encrypt_hsubs = True
        if hsubs and encrypt_hsubs:
            self.save_hsubs(hsubs)
        return hsubs

    def append_messages_to_list(self, read_messages, messages, messages_without_date):
        # check which folder to read the files from
        if read_messages:
            path = self.directory_read_messages
        else:
            path = self.directory_unread_messages
        files = files_in_path(path)
        for file_name in files:
            if re.match('message_' + self.nym.address + '_.*', file_name):
                file_path = path + '/' + file_name
                data = read_data(file_path)
                if read_messages:
                    decrypted_data = decrypt_data(self.gpg, data, self.nym.passphrase)
                    if decrypted_data:
                        data = decrypted_data
                    elif not search_pgp_message(data):
                        encrypted_data = encrypt_data(self.gpg, data, self.nym.address, self.nym.fingerprint,
                                                      self.nym.passphrase)
                        if encrypted_data:
                            save_data(encrypted_data, file_path)
                            self.debug(file_path.split('/')[-1] + ' is now encrypted')
                new_message = message.Message(not read_messages, data, file_path)
                if new_message.date:
                    messages.append(new_message)
                else:
                    messages_without_date.append(new_message)

    def retrieve_messages_from_disk(self):
        messages = []
        messages_without_date = []
        self.append_messages_to_list(False, messages, messages_without_date)
        self.append_messages_to_list(True, messages, messages_without_date)
        messages = sorted(messages, key=lambda item: item.date, reverse=True)
        messages += messages_without_date
        return messages

    def send_create(self, ephemeral, hsub, name, duration):
        recipient = 'config@' + self.nym.server
        pubkey, fingerprint = generate_key(self.gpg, name, self.nym.address, self.nym.passphrase, duration)
        generate_db(self.directory_db, fingerprint, ephemeral, self.nym.passphrase)
        data = 'ephemeral: ' + ephemeral + '\nhsub: ' + hsub + '\n' + pubkey

        self.nym.fingerprint = fingerprint
        self.nym.hsub = hsub
        success, info, ciphertext = self.encrypt_and_send(data, recipient, self.nym)
        if success:
            db_name = self.directory_db + '/' + self.nym.fingerprint + '.db'
            self.axolotl = Axolotl(self.nym.fingerprint, db_name, self.nym.passphrase)
            self.add_hsub(self.nym)
        return success, info, ciphertext

    def send_message(self, target_address, subject, content):
        recipient = 'send@' + self.nym.server
        msg = email.message_from_string('To: ' + target_address +
                                        '\nSubject: ' + subject +
                                        '\n' + content).as_string().strip()

        self.axolotl.loadState(self.nym.fingerprint, 'a')
        ciphertext = b2a_base64(self.axolotl.encrypt(msg)).strip()
        self.axolotl.saveState()

        lines = [ciphertext[i:i + 64] for i in xrange(0, len(ciphertext), 64)]
        pgp_message = '-----BEGIN PGP MESSAGE-----\n\n'
        for line in lines:
            pgp_message += line + '\n'
        pgp_message += '-----END PGP MESSAGE-----\n'

        return self.encrypt_and_send(pgp_message, recipient, self.nym)

    def send_config(self, ephemeral='', hsub='', name=''):
        db_file = self.directory_db + '/' + self.nym.fingerprint + '.db'
        recipient = 'config@' + self.nym.server
        ephemeral_line = ''
        hsub_line = ''
        name_line = ''

        if ephemeral:
            ephemeral_line = 'ephemeral: ' + str(ephemeral) + '\n'
        if hsub:
            hsub_line = 'hsub: ' + str(hsub) + '\n'
        if name:
            name_line = 'name: ' + str(name) + '\n'

        success = info = ciphertext = None
        data = ephemeral_line + hsub_line + name_line
        if data != '':
            success, info, ciphertext = self.encrypt_and_send(data, recipient, self.nym)
            if success:
                if ephemeral:
                    if os.path.exists(db_file):
                        os.unlink(db_file)
                    generate_db(self.directory_db, self.nym.fingerprint, ephemeral, self.nym.passphrase)
                if hsub:
                    self.nym.hsub = hsub
                    self.add_hsub(self.nym)
        return success, info, ciphertext

    def send_delete(self):
        recipient = 'config@' + self.nym.server
        db_file = self.directory_db + '/' + self.nym.fingerprint + '.db'

        data = 'delete: yes'
        success, info, ciphertext = self.encrypt_and_send(data, recipient, self.nym)
        if success:
            if os.path.exists(db_file):
                os.unlink(db_file)
            self.delete_hsub(self.nym)
            # delete secret key
            self.gpg.delete_keys(self.nym.fingerprint, True)
            # delete public key
            self.gpg.delete_keys(self.nym.fingerprint)
        return success, info, ciphertext

    def encrypt_and_send(self, data, recipient, nym):
        ciphertext = encrypt_data(self.gpg, data, recipient, nym.fingerprint, nym.passphrase)
        if ciphertext:
            success = True
            if self.output_method == 'manual':
                info = 'Send the following message to ' + recipient
                copy_to_clipboard(ciphertext)
                info += '\nIt has been copied to the clipboard'
            else:
                data = 'To: ' + recipient + '\nSubject: test\n\n' + ciphertext
                if self.send_data(data):
                    info = 'The following message was successfully sent to ' + recipient
                else:
                    info = 'ERROR! The following message could not be sent to ' + recipient
                    success = False
            info += '\n\n'
            return success, info, ciphertext
        else:
            raise errors.IncorrectPassphraseError()

    def send_data(self, data):
        if self.output_method == 'mixmaster':
            p = subprocess.Popen([self.file_mix_binary, '-m'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        elif self.output_method == 'sendmail':
            p = subprocess.Popen(['sendmail', '-t'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        else:
            self.debug('Invalid send choice')
            return False
        output, output_error = p.communicate(data)
        if output_error:
            return False
        if output or output == '':
            return True

    def count_unread_messages(self):
        counter = {}
        messages = files_in_path(self.directory_unread_messages)
        for m in messages:
            nym = re.search('(?<=message_).+(?=_.{5}.txt)', m)
            if nym:
                try:
                    counter[nym.group()] += 1
                except KeyError:
                    counter[nym.group()] = 1
        return counter

    def start_aampy(self):
        self.aampy.reset()

        self.thread_aampy_wait = threading.Thread(target=self.wait_for_aampy)
        self.thread_aampy_wait.daemon = True
        self.thread_aampy = threading.Thread(target=self.aampy.retrieve_messages, args=(self.hsubs,))
        self.thread_aampy.daemon = True

        self.thread_aampy_wait.start()
        self.thread_aampy.start()

    def stop_aampy(self):
        self.aampy.stop()

    def wait_for_aampy(self):
        self.aampy.event.wait()
        if self.hsubs and self.aampy.timestamp:
            self.hsubs['time'] = self.aampy.timestamp
            self.save_hsubs(self.hsubs)

    def decrypt_ephemeral_data(self, data):
        ciphertext = None
        self.axolotl.loadState(self.nym.fingerprint, 'a')
        # workaround to suppress prints by pyaxo
        sys.stdout = open(os.devnull, 'w')
        try:
            ciphertext = self.axolotl.decrypt(a2b_base64(data)).strip()
        except SystemExit:
            sys.stdout = sys.__stdout__
            self.debug('Error while decrypting message')
        else:
            sys.stdout = sys.__stdout__
            self.axolotl.saveState()
        return ciphertext

    def decrypt_ephemeral_message(self, msg):
        exp = re.compile('^[A-Za-z0-9+\/=]+\Z')
        buf = msg.content.splitlines()
        data = ''
        for item in buf:
            if len(item.strip()) % 4 == 0 and exp.match(item) and len(
                    item.strip()) <= 64 and not item.startswith(' '):
                data += item
        ciphertext = self.decrypt_ephemeral_data(data)
        self.delete_message_from_disk(msg)
        if ciphertext:
            self.debug('Ephemeral layer decrypted')
            plaintext = decrypt_data(self.gpg, ciphertext, self.nym.passphrase)
            if plaintext:
                self.debug('Asymmetric layer decrypted')
            else:
                plaintext = ciphertext
                if search_pgp_message(ciphertext):
                    self.debug('Asymmetric layer not decrypted')
                    plaintext = 'The asymmetric layer encrypted by the server could not be decrypted:\n\n' + ciphertext
            return message.Message(False, plaintext, msg.identifier)
        else:
            raise errors.UndecipherableMessageError()

    def encrypt_e2ee_data(self, data, recipient, signer=None, passphrase=''):
        """
        Return ciphertext of end-to-end encrypted data using the user's keyring

        recipient and signer are expected to be fingerprints (strings) or a dictionary with the same format as the one
        returned by gpg.list_keys()

        signer is optional, in case signing is not intended
        """

        try:
            recipient = recipient['fingerprint']
        except TypeError:
            # it might be a string with the fingerprint
            pass

        try:
            signer = signer['fingerprint']
        except TypeError:
            # it might be a string with the fingerprint
            pass

        ciphertext = self.user_gpg.encrypt(data, recipient, sign=signer, passphrase=passphrase, always_trust=True)
        if ciphertext:
            return str(ciphertext)
        else:
            text = ciphertext.status.capitalize()
            if not text:
                text = 'Unknown error'
            raise errors.NymphemeralError('GPG Error', text + '!')

    def decrypt_e2ee_message(self, msg, passphrase=''):
        """Return plaintext of end-to-end encrypted message using the user's keyring"""

        data = search_pgp_message(msg.content)
        if not data:
            self.debug('Not a PGP message to be decrypted')
            raise errors.UndecipherableMessageError()

        result = self.user_gpg.decrypt(data, passphrase=passphrase)
        gpg_info = ''

        if result.ok:
            self.debug('End-to-end layer decrypted')

            for line in result.stderr.split('\n'):
                info = re.match('(\[GNUPG:\] )(.*)', line)
                if not info:
                    gpg_info += line + '\n'

            if not gpg_info:
                gpg_info = 'GPG information not available\n'

            headers = str(msg.processed_message).split(data)[0]
            full_msg = headers + gpg_info + result.data

            return message.Message(False, full_msg, msg.identifier)
        else:
            self.debug('End-to-end layer not decrypted')
            raise errors.UndecipherableMessageError()

    def save_message_to_disk(self, msg):
        try:
            new_identifier = self.directory_read_messages + '/' + msg.identifier.split('/')[-1]
            data = msg.processed_message.as_string()
            ciphertext = encrypt_data(self.gpg, data, self.nym.address, self.nym.fingerprint, self.nym.passphrase)
            if ciphertext:
                data = ciphertext
            else:
                self.debug('Message encryption failed. Will be saved as plain text')
            if save_data(data, new_identifier):
                self.debug('Message saved to disk')
                return new_identifier
            else:
                self.debug('Message could not be saved')
        except IOError:
            print 'Error while saving to disk' + ':', sys.exc_info()[0]
        return None

    def delete_message_from_disk(self, msg):
        try:
            if os.path.exists(msg.identifier):
                os.unlink(msg.identifier)
                self.debug('Message deleted from disk')
            return True
        except IOError:
            print 'Error while deleting from disk' + ':', sys.exc_info()[0]
        return False
