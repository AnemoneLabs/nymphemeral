import re

from errors import InvalidEmailAddressError


class Nym(object):
    def __init__(self, address, passphrase=None, fingerprint=None, hsub=None):
        self._server = None
        self._address = None

        self.address = address
        self.passphrase = passphrase
        self.fingerprint = fingerprint
        self.hsub = hsub

    @property
    def server(self):
        return self._server

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, address):
        if re.match(r'[^@]+@[^@]+\.[^@]+', address):
            self._server = address.split('@')[1]
            self._address = address
        else:
            raise InvalidEmailAddressError(address)
