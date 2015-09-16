import hashlib
import logging
import os
import re
import subprocess
import sys
import time
from binascii import b2a_base64, a2b_base64
from ConfigParser import ConfigParser, MissingSectionHeaderError, NoOptionError, NoSectionError
from email import message_from_string
from threading import Thread
from Tkinter import Tk

import gnupg
from pyaxo import Axolotl

import errors
from __init__ import LINESEP
from __init__ import PATHSEP
from __init__ import logger
from aampy import AAMpy
from message import Message
from nym import Nym
from session import Session


USER_PATH = os.path.expanduser('~')
NYMPHEMERAL_PATH = os.path.join(USER_PATH, '.config', 'nymphemeral')
CONFIG_FILE = os.path.join(NYMPHEMERAL_PATH, 'nymphemeral.cfg')
OUTPUT_METHOD = {
    'mixmaster': 1,
    'sendmail': 2,
    'manual': 3,
}
DEBUG_LOGGER_LEVEL = 'debug'
DEFAULT_LOGGER_LEVEL = 'warning'
LOGGER_LEVEL = {
    DEBUG_LOGGER_LEVEL: logging.DEBUG,
    'info': logging.INFO,
    DEFAULT_LOGGER_LEVEL: logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL,
}

MIX_VERSION = 'Mixmaster 3'
MIX_BINS = [
    os.path.join(USER_PATH, 'Mix', 'mixmaster'),
    'mixmaster',
]
MIX_CONFIGS = [
    os.path.join(USER_PATH, 'Mix', 'mix.cfg'),
    os.path.join(USER_PATH, '.Mix', 'mix.cfg'),
]


log = logging.getLogger(__name__)


def add_to_head(element, elements):
    """Add an element to the head of a list, removing duplicates of it"""
    l = [element]
    for e in elements:
        if e != element:
            l.append(e)
    return l


def versions_match(binary, version):
    """Call --version on the binary. Return if starts with the version given"""
    try:
        v = subprocess.check_output([binary, '--version']).strip()
    except (OSError, AttributeError):
        return False
    else:
        return v.startswith(version)


def working_binary(binaries):
    """From a list of binaries, return the first to match with MIX_VERSION"""
    for b in binaries:
        if versions_match(b, MIX_VERSION):
            return b
    return None


def existing_path(paths):
    """From a list of file paths, return the first one that exists"""
    for p in paths:
        if os.path.exists(p):
            return p
    return None


def files_in_path(path):
    return [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]


def create_directory(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)


def create_dictionary(string):
    return dict(t.split() for t in string.strip().splitlines())


def search_block(data, beginning, end):
    """
    Return the first block found in the format:
        beginning
        <content>
        end
    Return None if beginning or end are not found
    """
    block = ''
    for line in data.splitlines():
        if block:
            block += line + LINESEP
            if line == end:
                return block
        elif line == beginning:
            block = line + LINESEP
    return None


def search_pgp_message(data):
    """Return the first PGP message found, return None otherwise"""
    return search_block(data, '-----BEGIN PGP MESSAGE-----', '-----END PGP MESSAGE-----')


def read_data(identifier):
    try:
        with open(identifier, 'r') as f:
            return f.read()
    except IOError:
        log.error('IOError while reading ' + identifier)
    return None


def save_data(data, identifier):
    try:
        with open(identifier, 'w') as f:
            f.write(data)
            return True
    except IOError:
        log.error('IOError while writing to ' + identifier)
    return False


def new_gpg(home, use_agent=False, throw_keyids=False):
    binary = '/usr/bin/gpg'

    options = ['--personal-digest-preferences=sha256',
               '--s2k-digest-algo=sha256']

    if use_agent:
        options.append('--use-agent')
    else:
        options.append('--no-use-agent')

    if throw_keyids:
        options.append('--throw-keyids')

    gpg = gnupg.GPG(binary,
                    home,
                    options=options)
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


def retrieve_key(gpg, search_query):
    """Find the ONLY key in the keyring for the search query

    :param gpg: The object that might have the data being searched
    :type gpg: gnupg.GPG
    :param str search_query: The search query
    :rtype: dict
    """
    try:
        search_query = search_query.lower()
    except AttributeError:
        raise errors.InvalidSearchQueryError()
    else:
        results = []
        keys = gpg.list_keys()

        for k in keys:
            if (k['keyid'].lower().endswith(search_query)
                    or k['fingerprint'].lower().endswith(search_query)):
                results.append(k)
            else:
                for sub in k['subkeys']:
                    if sub[0].lower().endswith(search_query):
                        results.append(k)
                        break
                else:
                    for uid in k['uids']:
                        if re.search(r'\b' + search_query + r'\b', uid,
                                     flags=re.IGNORECASE):
                            results.append(k)
                            break
        if results:
            for r in results[1:]:
                if r['fingerprint'] != results[0]['fingerprint']:
                    raise errors.AmbiguousUidError(search_query)
            return results[0]
        else:
            raise errors.KeyNotFoundError(search_query)


def retrieve_fingerprint(gpg, search_query):
    """Find the ONLY fingerprint in the keyring for the search query

    :param gpg: The object that might have the data being searched
    :type gpg: gnupg.GPG
    :param str search_query: The search query
    :rtype: str
    """
    return retrieve_key(gpg, search_query)['fingerprint']


def format_key_info(key):
    """
    Process a dictionary with key information and return it in a format similar to GPG's

    key should be a dictionary in the same format as the one returned by gpg.list_keys()

    The resulting string will be in the format:
        Username <user@domain>
        4096-bit key, ID 31415926, expires 2015-03-14
    """
    details = [
        key['length'] + '-bit key',
        'ID ' + key['keyid'][-8:],
    ]
    try:
        expiration = float(key['expires'])
    except ValueError:
        pass
    else:
        details.append('expires ' + time.strftime('%Y-%m-%d',
                                                  time.gmtime(expiration)))

    return LINESEP.join(key['uids'] + [', '.join(details)] + [''])


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
    t = Tk()
    t.withdraw()
    t.clipboard_clear()
    t.clipboard_append(data)
    t.destroy()


def create_axolotl(nym, directory):
    # workaround to suppress prints by pyaxo
    sys.stdout = open(os.devnull, 'w')
    try:
        axolotl = Axolotl(name=nym.fingerprint,
                          dbname=os.path.join(directory, nym.fingerprint + '.db'),
                          dbpassphrase=nym.passphrase)
    except SystemExit:
        sys.stdout = sys.__stdout__
        raise errors.IncorrectPassphraseError()
    else:
        sys.stdout = sys.__stdout__
        return axolotl


def create_state(axolotl, other_name, mkey):
    if os.path.exists(axolotl.dbname):
        os.unlink(axolotl.dbname)
    # Based on the latest protocol specification (Oct/2014), Alice is
    # the one that starts ratcheting the keys. Therefore, she needs
    # needs Bob's Diffie-Hellman Ratchet Key (DHR). Since the nym
    # already sends the master key to the nym server to be created,
    # it makes more sense to assign mode Bob (False) to the nym and
    # Alice (True) to the nym server, so that the ratchet key is also
    # sent in the same message.
    axolotl.createState(other_name=other_name,
                        mkey=hashlib.sha256(mkey).digest(),
                        mode=False)
    axolotl.saveState()


class Client:
    def __init__(self):
        self._cfg = ConfigParser()

        self.use_agent = None
        self.directory_base = None
        self.directory_db = None
        self.directory_read_messages = None
        self.directory_unread_messages = None
        self.file_hsub = None
        self.file_encrypted_hsub = None
        self.logger_level = None
        self.output_method = None
        self.file_mix_binary = None
        self.file_mix_cfg = None
        self.chain = None
        self._check_base_files()

        # create a GPG instance using nymphemeral's base directory as home
        self.gpg = new_gpg(self.directory_base)

        self._session = Session()

        # attributes to handle aampy (to retrieve new messages) using threads
        self.aampy = self._initialize_aampy()
        self._thread_aampy = None
        self._thread_aampy_wait = None

        log.debug('Initialized')

    @property
    def nym_address(self):
        return self._session.nym.address

    @property
    def chain_info(self):
        info = 'Mix Chain: '
        try:
            info += self.chain
        except TypeError:
            info += 'Unknown'
        return info

    def _check_base_files(self):
        try:
            self.load_configs()
            create_directory(self.directory_db)
            create_directory(self.directory_read_messages)
            create_directory(self.directory_unread_messages)
        except IOError:
            log.error('IOError while creating base files')
            raise

    def _check_mixmaster(self):
        self.file_mix_cfg = None
        self.chain = None

        # check Mixmaster binary
        binary = self._cfg.get('mixmaster', 'binary')
        binaries = add_to_head(binary, MIX_BINS)
        self.file_mix_binary = working_binary(binaries)
        if self.file_mix_binary:
            log.info('Mixmaster binary works')
            self._cfg.set('mixmaster', 'binary', self.file_mix_binary)

            # check Mixmaster configs and chain
            cfg = self._cfg.get('mixmaster', 'cfg')
            cfgs = add_to_head(cfg, MIX_CONFIGS)
            self.file_mix_cfg = existing_path(cfgs)
            if self.file_mix_cfg:
                log.info('Mixmaster config file found at ' + self.file_mix_cfg)
                self._cfg.set('mixmaster', 'cfg', self.file_mix_cfg)
                try:
                    with open(self.file_mix_cfg, 'r') as config:
                        lines = config.readlines()
                        for line in lines:
                            s = re.match(r'CHAIN (.+)', line)
                            if s:
                                self.chain = s.group(1)
                                log.info('Mix chain in use: ' + self.chain)
                                break
                        else:
                            log.info('Mix chain was not found')
                except IOError:
                    log.error('IOError when reading ' + self.file_mix_cfg)
                    self.file_mix_cfg = None
            else:
                log.info('Mixmaster config file was not found')
        else:
            log.info('Mixmaster binary was not found or is not appropriate')

    def _initialize_aampy(self):
        return AAMpy(self.directory_unread_messages,
                     group=self._cfg.get('newsgroup', 'group'),
                     server=self._cfg.get('newsgroup', 'server'),
                     port=self._cfg.get('newsgroup', 'port'))

    def _wait_for_aampy(self):
        self.aampy.event.wait()
        if self._session.hsubs and self.aampy.timestamp:
            self._session.hsubs['time'] = self.aampy.timestamp
            self.save_hsubs(self._session.hsubs)

    def _decrypt_hsubs_file(self):
        if os.path.exists(self.file_encrypted_hsub):
            encrypted_data = read_data(self.file_encrypted_hsub)
            return decrypt_data(self.gpg,
                                encrypted_data,
                                self._session.nym.passphrase)
        else:
            log.info('Decryption of ' + self.file_encrypted_hsub + ' failed. '
                     'It does not exist')
        return None

    def _append_messages_to_list(self, read_messages, messages, messages_without_date):
        # check which directory to read the files from
        if read_messages:
            path = self.directory_read_messages
        else:
            path = self.directory_unread_messages
        files = files_in_path(path)
        for file_name in files:
            if re.match('message_' + self._session.nym.address + '_.*',
                        file_name):
                file_path = os.path.join(path, file_name)
                data = read_data(file_path)
                if read_messages:
                    decrypted_data = decrypt_data(self.gpg,
                                                  data,
                                                  self._session.nym.passphrase)
                    if decrypted_data:
                        data = decrypted_data
                    elif not search_pgp_message(data):
                        encrypted_data = encrypt_data(
                            self.gpg,
                            data,
                            self._session.nym.address,
                            self._session.nym.fingerprint,
                            self._session.nym.passphrase
                        )
                        if encrypted_data:
                            save_data(encrypted_data, file_path)
                            log.debug(file_path.split(PATHSEP)[-1] + ' is now'
                                      'encrypted')
                new_message = Message(not read_messages, data, file_path)
                if new_message.date:
                    messages.append(new_message)
                else:
                    messages_without_date.append(new_message)

    def _encrypt_e2ee_data(self, data, target,
                           signer=None, passphrase=None, throw_keyids=False):
        """Return ciphertext of end-to-end encrypted data

        :param str data: The data to be encrypted
        :param str target: The fingerprint of the target
        :param str signer: The fingerprint of the signer
        :param str passphrase: The passphrase of the signer
        :param bool throw_keyids: Flag used to throw the target's key ID
        :rtype: str
        """
        gpg = new_gpg(self.directory_base, self.use_agent, throw_keyids)
        ciphertext = gpg.encrypt(data,
                                 target,
                                 sign=signer,
                                 passphrase=passphrase,
                                 always_trust=True)
        if ciphertext:
            return str(ciphertext)
        else:
            text = ciphertext.status.capitalize()
            if not text:
                text = 'Unknown error'
            raise errors.NymphemeralError('GPG Error', text + '!')

    def _sign_data(self, data, signer, passphrase=None):
        """Return data signed by the fingerprint given

        :param str data: The data to be signed
        :param str signer: The fingerprint of the signer
        :param str passphrase: The passphrase of the signer
        :rtype: str
        """
        gpg = new_gpg(self.directory_base, self.use_agent)
        result = gpg.sign(data, keyid=signer, passphrase=passphrase)
        if result:
            return str(result)
        else:
            error = result.stderr.lower()
            bad_pass_error = 'bad passphrase'
            need_pass_error = 'need_passphrase'
            skey_error = 'secret key not available'
            if bad_pass_error in error or need_pass_error in error:
                raise errors.IncorrectPassphraseError()
            elif skey_error in error:
                raise errors.SecretKeyNotFoundError(signer)
            else:
                raise errors.NymphemeralError('GPG Error', result.stderr)

    def load_configs(self):
        try:
            # load default configs
            self._cfg.add_section('gpg')
            self._cfg.set('gpg', 'use_agent', 'True')
            self._cfg.add_section('main')
            self._cfg.set('main', 'base_dir', NYMPHEMERAL_PATH)
            self._cfg.set('main', 'db_dir',
                          os.path.join('%(base_dir)s', 'db'))
            self._cfg.set('main', 'messages_dir',
                          os.path.join('%(base_dir)s', 'messages'))
            self._cfg.set('main', 'read_dir',
                          os.path.join('%(messages_dir)s', 'read'))
            self._cfg.set('main', 'unread_dir',
                          os.path.join('%(messages_dir)s', 'unread'))
            self._cfg.set('main', 'hsub_file',
                          os.path.join('%(base_dir)s', 'hsubs.txt'))
            self._cfg.set('main', 'encrypted_hsub_file',
                          os.path.join('%(base_dir)s', 'encrypted_hsubs.txt'))
            self._cfg.set('main', 'logger_level', 'warning')
            self._cfg.set('main', 'output_method', 'manual')
            self._cfg.add_section('mixmaster')
            self._cfg.set('mixmaster', 'binary', MIX_BINS[0])
            self._cfg.set('mixmaster', 'cfg', MIX_CONFIGS[0])
            self._cfg.add_section('newsgroup')
            self._cfg.set('newsgroup', 'base_dir', NYMPHEMERAL_PATH)
            self._cfg.set('newsgroup', 'group', 'alt.anonymous.messages')
            self._cfg.set('newsgroup', 'server', 'localhost')
            self._cfg.set('newsgroup', 'port', '119')

            # parse existing configs in case:
            #   - new versions add/remove sections/options
            #   - user modifies the file inappropriately
            # a working config file will be written to disk after the process,
            # overwriting the existing one
            if os.path.exists(CONFIG_FILE):
                saved_cfg = ConfigParser()
                try:
                    saved_cfg.read(CONFIG_FILE)
                except MissingSectionHeaderError:
                    pass
                else:
                    for section in self._cfg.sections():
                        for option in self._cfg.options(section):
                            try:
                                self._cfg.set(section, option,
                                              saved_cfg.get(section, option))
                            except NoSectionError:
                                break
                            except NoOptionError:
                                pass
            else:
                create_directory(NYMPHEMERAL_PATH)

            # make sure to use a valid level for the logger
            log_sec = 'main'
            log_opt = 'logger_level'
            log_cfg_str = self._cfg.get(log_sec, log_opt).lower()
            valid_level = log_cfg_str in LOGGER_LEVEL

            if valid_level:
                self.logger_level = log_cfg_str
            else:
                self.logger_level = DEFAULT_LOGGER_LEVEL
            log_cfg_int = LOGGER_LEVEL[self.logger_level]
            if logger.getEffectiveLevel() != log_cfg_int:
                logger.setLevel(log_cfg_int)

            if not valid_level:
                log.warn('The value "%s" for %s from [%s] section of %s is '
                         'incorrect. Should be: %s. Using the default: %s'
                         % (log_cfg_str, log_opt, log_sec, CONFIG_FILE,
                            '/'.join(LOGGER_LEVEL.keys()),
                            self.logger_level))

            self._check_mixmaster()

            # make sure to enable Mixmaster only if the the binary and config
            # file have been found
            output_method = self._cfg.get('main', 'output_method')
            if output_method == 'mixmaster' and not (self.file_mix_binary or
                                                     self.file_mix_cfg):
                output_method = 'manual'
                self._cfg.set('main', 'output_method', output_method)
            self.output_method = output_method

            self.save_configs()

            self.use_agent = self._cfg.getboolean('gpg', 'use_agent')
            self.directory_base = self._cfg.get('main', 'base_dir')
            self.directory_db = self._cfg.get('main', 'db_dir')
            self.directory_read_messages = self._cfg.get('main', 'read_dir')
            self.directory_unread_messages = self._cfg.get('main', 'unread_dir')
            self.file_hsub = self._cfg.get('main', 'hsub_file')
            self.file_encrypted_hsub = self._cfg.get('main', 'encrypted_hsub_file')

            log.debug('Configs have been loaded')
        except IOError:
            log.error('Configs could not be loaded. IOError while reading ' +
                      CONFIG_FILE)
            raise

    def save_configs(self):
        with open(CONFIG_FILE, 'w') as config_file:
            self._cfg.write(config_file)

    def update_configs(self):
        self._cfg.set('gpg', 'use_agent', self.use_agent)
        self._cfg.set('main', 'output_method', self.output_method)

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
                    config_match = re.search(r'\bconfig@(\S+)\b', uid, flags=re.IGNORECASE)
                if not send_match:
                    send_match = re.search(r'\bsend@(\S+)+\b', uid, flags=re.IGNORECASE)
                if not url_match:
                    url_match = re.search(r'\burl@(\S+)\b', uid, flags=re.IGNORECASE)
            if config_match and send_match and url_match:
                server = config_match.group(1)
                servers[server] = item['fingerprint']
        return servers

    def retrieve_nyms(self):
        servers = self.retrieve_servers()
        nyms = []
        keys = self.gpg.list_keys(secret=True)
        for item in keys:
            if len(item['uids']) == 1:
                search = re.search(r'\b(\S+@(\S+))\b', item['uids'][0])
                if search and search.group(2) in servers:
                    nym = Nym(address=search.group(1),
                              fingerprint=item['fingerprint'])
                    nyms.append(nym)
        return nyms

    def start_session(self, nym, use_agent=False, output_method='manual', creating_nym=False):
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
            self._session.axolotl = create_axolotl(nym, self.directory_db)
        self._session.nym = nym
        self._session.hsubs = self.retrieve_hsubs()
        if not creating_nym:
            self._session.nym.hsub = self._session.hsubs[nym.address]
        self.check_configs(use_agent, output_method)

    def end_session(self):
        self._session = Session()

    def check_configs(self, use_agent, output_method):
        update = False

        if use_agent != self.use_agent:
            self.use_agent = use_agent
            update = True

        if output_method != self.output_method:
            self.output_method = output_method
            update = True

        if update:
            self.update_configs()
            self.save_configs()

    def save_hsubs(self, hsubs):
        output_file = self.file_hsub
        data = ''
        for key, item in hsubs.iteritems():
            data += key + ' ' + str(item) + LINESEP
        # check if the nym has access or can create the encrypted hSub passphrases file
        if self._session.nym.fingerprint \
                and (not os.path.exists(self.file_encrypted_hsub)
                     or self._decrypt_hsubs_file()):
            nyms = self.retrieve_nyms()
            recipients = []
            for n in nyms:
                recipients.append(n.address)
            result = encrypt_data(self.gpg,
                                  data,
                                  recipients,
                                  self._session.nym.fingerprint,
                                  self._session.nym.passphrase)
            if result:
                output_file = self.file_encrypted_hsub
                data = result
        if save_data(data, output_file):
            if output_file == self.file_encrypted_hsub:
                if os.path.exists(self.file_hsub):
                    os.unlink(self.file_hsub)
                log.info('hSub passphrases were encrypted and saved to ' +
                         self.file_encrypted_hsub)
            return True
        else:
            return False

    def add_hsub(self, nym):
        self._session.hsubs[nym.address] = nym.hsub
        return self.save_hsubs(self._session.hsubs)

    def delete_hsub(self, nym):
        del self._session.hsubs[nym.address]
        # check if there are no hSub passphrases anymore
        if not self._session.hsubs or len(self._session.hsubs) == 1 \
                and 'time' in self._session.hsubs:
            if self._decrypt_hsubs_file():
                hsub_file = self.file_encrypted_hsub
            else:
                hsub_file = self.file_hsub
            try:
                os.unlink(hsub_file)
            except IOError:
                log.error('IOError while manipulating ' +
                          hsub_file.split(PATHSEP)[-1])
                return False
        else:
            return self.save_hsubs(self._session.hsubs)
        return True

    def retrieve_hsubs(self):
        hsubs = {}
        encrypt_hsubs = False

        if os.path.exists(self.file_hsub):
            hsubs = create_dictionary(read_data(self.file_hsub))

        if os.path.exists(self.file_encrypted_hsub):
            decrypted_data = self._decrypt_hsubs_file()
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

    def retrieve_messages_from_disk(self):
        messages = []
        messages_without_date = []
        self._append_messages_to_list(False, messages, messages_without_date)
        self._append_messages_to_list(True, messages, messages_without_date)
        messages = sorted(messages, key=lambda item: item.date, reverse=True)
        messages += messages_without_date
        return messages

    def send_create(self, ephemeral, hsub, name, duration):
        ephemeral = ephemeral.strip()
        hsub = hsub.strip()
        name = name.strip()
        duration = duration.strip()

        if not ephemeral:
            raise errors.InvalidEphemeralKeyError()
        if not hsub:
            raise errors.InvalidHsubError()
        if not name:
            raise errors.InvalidNameError()
        if not re.match(r'\d+[dwmy]{0,1}$', duration, flags=re.IGNORECASE):
            raise errors.InvalidDurationError()

        pubkey, fingerprint = generate_key(self.gpg,
                                           name,
                                           self._session.nym.address,
                                           self._session.nym.passphrase,
                                           duration)
        nym = Nym(self._session.nym.address,
                  self._session.nym.passphrase,
                  fingerprint,
                  hsub)
        axolotl = create_axolotl(nym, self.directory_db)

        lines = []
        lines.append('ephemeral: ' + ephemeral)
        lines.append('ratchet: ' + b2a_base64(axolotl.state['DHRs']).strip())
        lines.append('hsub: ' + hsub)
        lines.append(pubkey)
        data = LINESEP.join(lines)

        success, info, ciphertext = self.encrypt_and_send(
            data,
            recipient='config@'+self._session.nym.server
        )
        if success:
            create_state(axolotl=axolotl,
                         other_name=self._session.nym.server,
                         mkey=ephemeral)
            self._session.axolotl = axolotl
            self._session.nym = nym
            self.add_hsub(self._session.nym)
        return success, info, ciphertext

    def send_message(self, target_address, body,
                     subject='', headers='',
                     e2ee_target='',
                     e2ee_signer='', passphrase=None,
                     throw_keyids=False):
        target_address = target_address.strip()
        body = body.strip()
        subject = subject.strip()
        headers = headers.strip()
        e2ee_target = e2ee_target.strip()
        e2ee_signer = e2ee_signer.strip()

        if not len(target_address):
            raise errors.EmptyTargetError()
        if not len(body):
            raise errors.EmptyBodyError()

        # check if end-to-end encryption is intended
        e2ee_target_info = ''
        if e2ee_target or e2ee_signer:
            if e2ee_target:
                e2ee_target_key = retrieve_key(self.gpg, e2ee_target)
                e2ee_target_fp = e2ee_target_key['fingerprint']
                e2ee_target_info = ('End-to-End Encryption to:' + LINESEP +
                                    format_key_info(e2ee_target_key) + LINESEP)
                if e2ee_signer:
                    # encrypt and sign
                    body = self._encrypt_e2ee_data(
                        data=body,
                        target=e2ee_target_fp,
                        signer=retrieve_fingerprint(self.gpg, e2ee_signer),
                        passphrase=passphrase,
                        throw_keyids=throw_keyids
                    )
                else:
                    # encrypt only
                    body = self._encrypt_e2ee_data(
                        data=body,
                        target=e2ee_target_fp,
                        throw_keyids=throw_keyids
                    )
            else:
                # sign only
                body = self._sign_data(
                    data=body,
                    signer=retrieve_fingerprint(self.gpg, e2ee_signer),
                    passphrase=passphrase
                )

        lines = []
        lines.append('To: ' + target_address)
        if len(subject):
            lines.append('Subject: ' + subject)
        for header in headers.splitlines():
            h = header.strip()
            if len(h):
                lines.append(h)
        lines.append('')
        lines.append(body)
        lines.append('')
        content = LINESEP.join(lines)
        msg = message_from_string(content).as_string()

        self._session.axolotl.loadState(self._session.nym.fingerprint,
                                        self._session.nym.server)
        ciphertext = b2a_base64(self._session.axolotl.encrypt(msg)).strip()
        self._session.axolotl.saveState()

        lines = [ciphertext[i:i + 64] for i in xrange(0, len(ciphertext), 64)]
        lines.insert(0, '-----BEGIN PGP MESSAGE-----' + LINESEP)
        lines.append('-----END PGP MESSAGE-----' + LINESEP)
        pgp_message = LINESEP.join(lines)

        success, info, ciphertext = self.encrypt_and_send(
            pgp_message,
            recipient='send@'+self._session.nym.server
        )
        return success, e2ee_target_info + info, ciphertext

    def send_config(self, ephemeral='', hsub='', name=''):
        ephemeral = ephemeral.strip()
        hsub = hsub.strip()
        name = name.strip()

        if not (ephemeral or hsub or name):
            raise errors.EmptyChangesError()

        axolotl = create_axolotl(self._session.nym, self.directory_db)

        lines = []
        if ephemeral:
            lines.append('ephemeral: ' + str(ephemeral))
            lines.append('ratchet: ' + b2a_base64(axolotl.state['DHRs']).strip())
        if hsub:
            lines.append('hsub: ' + str(hsub))
        if name:
            lines.append('name: ' + str(name))
        lines.append('')
        data = LINESEP.join(lines)

        success, info, ciphertext = self.encrypt_and_send(
            data,
            recipient='config@'+self._session.nym.server
        )
        if success:
            if ephemeral:
                create_state(axolotl=axolotl,
                             other_name=self._session.nym.server,
                             mkey=ephemeral)
            if hsub:
                self._session.nym.hsub = hsub
                self.add_hsub(self._session.nym)
        return success, info, ciphertext

    def send_delete(self):
        db_file = os.path.join(self.directory_db,
                               self._session.nym.fingerprint + '.db')

        success, info, ciphertext = self.encrypt_and_send(
            data='delete: yes',
            recipient='config@'+self._session.nym.server
        )
        if success:
            if os.path.exists(db_file):
                os.unlink(db_file)
            self.delete_hsub(self._session.nym)
            # delete secret key
            self.gpg.delete_keys(self._session.nym.fingerprint, True)
            # delete public key
            self.gpg.delete_keys(self._session.nym.fingerprint)
        return success, info, ciphertext

    def encrypt_and_send(self, data, recipient):
        ciphertext = encrypt_data(self.gpg, data, recipient,
                                  self._session.nym.fingerprint,
                                  self._session.nym.passphrase)
        if ciphertext:
            success = True
            if self.output_method == 'manual':
                info = 'Send the following message to ' + recipient
                copy_to_clipboard(ciphertext)
                info += LINESEP + 'It has been copied to the clipboard'
            else:
                data = 'To: ' + recipient + LINESEP*2 + ciphertext
                if self.send_data(data):
                    info = 'The following message was successfully sent to ' + recipient
                else:
                    info = 'ERROR! The following message could not be sent to ' + recipient
                    success = False
            info += LINESEP*2
            return success, info, ciphertext
        else:
            raise errors.IncorrectPassphraseError()

    def send_data(self, data):
        if self.output_method == 'mixmaster':
            p = subprocess.Popen([self.file_mix_binary, '-m'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        elif self.output_method == 'sendmail':
            p = subprocess.Popen(['sendmail', '-t'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        else:
            log.error('Invalid send choice: ' + self.output_method)
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

        self._thread_aampy_wait = Thread(target=self._wait_for_aampy)
        self._thread_aampy_wait.daemon = True
        self._thread_aampy = Thread(target=self.aampy.retrieve_messages,
                                    args=(self._session.hsubs,))
        self._thread_aampy.daemon = True

        self._thread_aampy_wait.start()
        self._thread_aampy.start()

    def stop_aampy(self):
        self.aampy.stop()

    def decrypt_ephemeral_data(self, data):
        ciphertext = None
        self._session.axolotl.loadState(self._session.nym.fingerprint,
                                        self._session.nym.server)
        # workaround to suppress prints by pyaxo
        sys.stdout = open(os.devnull, 'w')
        try:
            ciphertext = self._session.axolotl.decrypt(a2b_base64(data)).strip()
        except SystemExit:
            sys.stdout = sys.__stdout__
            log.info('Error while decrypting message')
        else:
            sys.stdout = sys.__stdout__
            self._session.axolotl.saveState()
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
            log.debug('Ephemeral layer decrypted')
            plaintext = decrypt_data(self.gpg,
                                     ciphertext,
                                     self._session.nym.passphrase)
            if plaintext:
                log.debug('Asymmetric layer decrypted')
            else:
                plaintext = ciphertext
                if search_pgp_message(ciphertext):
                    log.debug('Asymmetric layer not decrypted')
                    plaintext = ('The asymmetric layer encrypted by the '
                                 'server could not be decrypted:' +
                                 LINESEP*2 +
                                 ciphertext)
            return Message(False, plaintext, msg.identifier)
        else:
            raise errors.UndecipherableMessageError()

    def decrypt_e2ee_message(self, msg, passphrase=None):
        """Return plaintext of end-to-end encrypted message using nymphemeral's keyring"""
        data = search_pgp_message(msg.content)
        if not data:
            log.debug('Not a PGP message to be decrypted')
            raise errors.UndecipherableMessageError()

        gpg = new_gpg(self.directory_base, self.use_agent)
        result = gpg.decrypt(data, passphrase=passphrase)
        gpg_info = ''

        if result.ok:
            log.debug('End-to-end layer decrypted')

            lines = result.stderr.splitlines()

            # filter what should be displayed to the user
            for i, line in enumerate(lines):
                if line.startswith('[GNUPG:]'):
                    continue

                if line.startswith('gpg: anonymous recipient; trying secret key'):
                    continue

                if line == 'gpg: encrypted with RSA key, ID 00000000':
                    continue

                if line == 'gpg: okay, we are the anonymous recipient.':
                    j = 1
                    line_id = lines[i - j]
                    while not line_id.startswith('gpg: anonymous recipient; trying secret key'):
                        j += 1
                        line_id = lines[i - j]
                    gpg_info = gpg_info + line_id + LINESEP

                gpg_info += line + LINESEP

            if not gpg_info:
                gpg_info = 'GPG information not available' + LINESEP

            headers = str(msg.processed_message).split(data)[0]
            full_msg = headers + gpg_info + result.data

            return Message(False, full_msg, msg.identifier)
        else:
            log.debug('End-to-end layer not decrypted')
            raise errors.UndecipherableMessageError()

    def save_message_to_disk(self, msg):
        try:
            new_identifier = os.path.join(self.directory_read_messages,
                                          msg.identifier.split(PATHSEP)[-1])
            data = msg.processed_message.as_string()
            ciphertext = encrypt_data(self.gpg,
                                      data,
                                      self._session.nym.address,
                                      self._session.nym.fingerprint,
                                      self._session.nym.passphrase)
            if ciphertext:
                data = ciphertext
            else:
                log.warn('Message encryption failed. Will be saved as plain'
                         'text')
            if save_data(data, new_identifier):
                log.info('Message saved to disk')
                msg.identifier = new_identifier
                return True
            else:
                log.error('Message could not be saved')
        except IOError:
            log.error('IOError while saving message to disk')
        return False

    def delete_message_from_disk(self, msg):
        try:
            if os.path.exists(msg.identifier):
                os.unlink(msg.identifier)
                log.info('Message deleted from disk')
            return True
        except IOError:
            log.error('IOError while deleting from disk')
        return False
