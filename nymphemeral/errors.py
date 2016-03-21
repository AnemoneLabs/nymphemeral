from . import LINESEP


class NymphemeralError(Exception):
    def __init__(self, title, message):
        self.title = title
        self.message = message


class AmbiguousUidError(NymphemeralError):
    def __init__(self, uid):
        super(AmbiguousUidError, self).__init__(
            title='Ambiguous UID',
            message='"' + uid +
                    '" has multiple fingerprints. Be more specific.'
        )


class InvalidEmailAddressError(NymphemeralError):
    def __init__(self, address):
        super(InvalidEmailAddressError, self).__init__(
            title='Invalid Email Address',
            message='"' + address + '" is not in a valid format.'
        )


class InvalidPassphraseError(NymphemeralError):
    def __init__(self):
        super(InvalidPassphraseError, self).__init__(
            title='Invalid Passphrase',
            message='The passphrase provided (empty) is not valid.'
        )


class InvalidSearchQueryError(NymphemeralError):
    def __init__(self):
        super(InvalidSearchQueryError, self).__init__(
            title='Invalid Search Query',
            message='The search query provided must be a string.'
        )


class NymservNotFoundError(NymphemeralError):
    def __init__(self, nymserv):
        super(NymservNotFoundError, self).__init__(
            title='Nym Server Not Found',
            message='"' + nymserv +
                    '" public key could not be found in the keyring.'
        )


class NymNotFoundError(NymphemeralError):
    def __init__(self, nym):
        super(NymNotFoundError, self).__init__(
            title='Nym Not Found',
            message='"' + nym + '" does not exist.'
        )


class NewsserverNotFoundError(NymphemeralError):
    def __init__(self, server, port):
        super(NewsserverNotFoundError, self).__init__(
            title='Socket Error',
            message='The server running on ' +
                    server + ':' + str(port) + ' could not be found.'
        )


class FingerprintNotFoundError(NymphemeralError):
    def __init__(self, query):
        super(FingerprintNotFoundError, self).__init__(
            title='Fingerprint Not Found',
            message='The fingerprint for "' + query +
                    '" could not be found in the keyring.'
        )


class KeyNotFoundError(NymphemeralError):
    def __init__(self, query):
        super(KeyNotFoundError, self).__init__(
            title='Key Not Found',
            message='The key for "' + query +
                    '" could not be found in the keyring.'
        )


class SecretKeyNotFoundError(NymphemeralError):
    def __init__(self, query):
        super(SecretKeyNotFoundError, self).__init__(
            title='Scret Key Not Found',
            message='The secret key for "' + query +
                    '" could not be found in the keyring.'
        )


class IncorrectPassphraseError(NymphemeralError):
    def __init__(self):
        super(IncorrectPassphraseError, self).__init__(
            title='Incorrect Passphrase',
            message='The passphrase provided is incorrect.'
        )


class InvalidHsubError(NymphemeralError):
    def __init__(self):
        super(InvalidHsubError, self).__init__(
            title='Invalid hSub Passphrase',
            message='The hSub passphrase provided (empty) is not valid.'
        )


class InvalidEphemeralKeyError(NymphemeralError):
    def __init__(self):
        super(InvalidEphemeralKeyError, self).__init__(
            title='Invalid Ephemeral Key',
            message='The ephemeral key provided (empty) is not valid.'
        )


class InvalidNameError(NymphemeralError):
    def __init__(self):
        super(InvalidNameError, self).__init__(
            title='Invalid Name',
            message='The pseudonymous name provided (empty) is not valid.'
        )


class InvalidDurationError(NymphemeralError):
    def __init__(self):
        super(InvalidDurationError, self).__init__(
            title='Invalid Duration',
            message=LINESEP.join([
                'The duration provided should be in the format:',
                '',
                '0 = key does not expire',
                '<n> = key expires in n days',
                '<n>w = key expires in n weeks',
                '<n>m = key expires in n months',
                '<n>y = key expires in n years'
            ])
        )


class UndecipherableMessageError(NymphemeralError):
    def __init__(self):
        super(UndecipherableMessageError, self).__init__(
            title='Undecipherable Message',
            message='The message could not be deciphered.'
        )


class EmptyTargetError(NymphemeralError):
    def __init__(self):
        super(EmptyTargetError, self).__init__(
            title='Empty Target',
            message='The message must have a target.'
        )


class EmptyBodyError(NymphemeralError):
    def __init__(self):
        super(EmptyBodyError, self).__init__(
            title='Empty Body',
            message='The message must have a body.'
        )


class EmptyChangesError(NymphemeralError):
    def __init__(self):
        super(EmptyChangesError, self).__init__(
            title='Empty Changes',
            message='The configuration message must have at least one change.'
        )
