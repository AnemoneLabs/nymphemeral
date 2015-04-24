class NymphemeralError(Exception):
    def __init__(self, title, message):
        self.title = title
        self.message = message


class AmbiguousUidError(NymphemeralError):
    def __init__(self, uid):
        self.title = 'Ambiguous UID'
        self.message = '"' + uid + '" has multiple fingerprints. Be more specific.'


class InvalidEmailAddressError(NymphemeralError):
    def __init__(self, address):
        self.title = 'Invalid Email Address'
        self.message = '"' + address + '" is not in a valid format.'


class InvalidPassphraseError(NymphemeralError):
    def __init__(self):
        self.title = 'Invalid Passphrase'
        self.message = 'The passphrase provided (empty) is not valid.'


class NymservNotFoundError(NymphemeralError):
    def __init__(self, nymserv):
        self.title = 'Nym Server Not Found'
        self.message = '"' + nymserv + '" public key could not be found in the keyring.'


class NymNotFoundError(NymphemeralError):
    def __init__(self, nym):
        self.title = 'Nym Not Found'
        self.message = '"' + nym + '" does not exist.'


class NewsserverNotFoundError(NymphemeralError):
    def __init__(self, server, port):
        self.title = 'Socket Error'
        self.message = 'The server running on ' + server + ':' + str(port) + ' could not be found.'


class FingerprintNotFoundError(NymphemeralError):
    def __init__(self, query):
        self.title = 'Fingerprint Not Found'
        self.message = 'The fingerprint for "' + query + '" could not be found in the keyring.'


class KeyNotFoundError(NymphemeralError):
    def __init__(self, query):
        self.title = 'Key Not Found'
        self.message = 'The key for "' + query + '" could not be found in the keyring.'


class SecretKeyNotFoundError(NymphemeralError):
    def __init__(self, query):
        self.title = 'Scret Key Not Found'
        self.message = 'The secret key for "' + query + '" could not be found in the keyring.'


class IncorrectPassphraseError(NymphemeralError):
    def __init__(self):
        self.title = 'Incorrect Passphrase'
        self.message = 'The passphrase provided is incorrect.'


class InvalidHsubError(NymphemeralError):
    def __init__(self):
        self.title = 'Invalid hSub Passphrase'
        self.message = 'The hSub passphrase provided (empty) is not valid.'


class InvalidEphemeralKeyError(NymphemeralError):
    def __init__(self):
        self.title = 'Invalid Ephemeral Key'
        self.message = 'The ephemeral key provided (empty) is not valid.'


class UndecipherableMessageError(NymphemeralError):
    def __init__(self):
        self.title = 'Undecipherable Message'
        self.message = 'The message could not be deciphered.'
