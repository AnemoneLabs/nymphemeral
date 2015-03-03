class NymphemeralError(Exception):
    def __init__(self):
        self.title = None
        self.message = None


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
    def __init__(self, nym):
        self.title = 'Fingerprint Not Found'
        self.message = 'The fingerprint for "' + nym + '" could not be found in the keyring.'


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
