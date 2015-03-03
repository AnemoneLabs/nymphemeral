import re

from errors import *


class Nym():
    def __init__(self, address, passphrase=None, fingerprint=None, hsub=None):
        if not re.match(r'[^@]+@[^@]+\.[^@]+', address):
            raise InvalidEmailAddressError(address)
        self.address = address
        self.passphrase = passphrase
        self.fingerprint = fingerprint
        self.hsub = hsub
        self.server = address.split('@')[1]
