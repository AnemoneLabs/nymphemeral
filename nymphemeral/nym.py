#!/usr/bin/env python


class Nym():
    def __init__(self, address, passphrase=None, fingerprint=None, hsub=None):
        self.address = address
        self.passphrase = passphrase
        self.fingerprint = fingerprint
        self.hsub = hsub
        self.server = address.split('@')[1]