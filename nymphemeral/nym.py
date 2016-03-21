import re
import time

from .errors import InvalidEmailAddressError


class Nym(object):
    def __init__(self, address, passphrase=None, fingerprint=None, hsub=None,
                 expiration_epoch=None):
        self._server = None
        self._address = None
        self._expiration_epoch = None
        self._expiration_date = None

        self.address = address
        self.passphrase = passphrase
        self.fingerprint = fingerprint
        self.hsub = hsub
        self.expiration_epoch = expiration_epoch

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

    @property
    def expiration_epoch(self):
        return self._expiration_epoch

    @expiration_epoch.setter
    def expiration_epoch(self, expiration_epoch):
        if expiration_epoch is None:
            expiration_date = None
        else:
            expiration_epoch = float(expiration_epoch)
            if expiration_epoch == 0:
                expiration_date = 'never'
            else:
                expiration_date = time.strftime(
                    '%Y-%m-%d',
                    time.localtime(expiration_epoch))
        self._expiration_epoch = expiration_epoch
        self._expiration_date = expiration_date

    @property
    def expiration_date(self):
        return self._expiration_date
