# encoding: utf-8

from logging import getLogger

from Crypto.PublicKey import RSA

C_KEY_FILENAME  = 'authserv.pem'
C_KEY_BITS      = 1024

class KeyManager():

    def __init__(self, filename=None):
        self.logger = getLogger('keymanager')
        try:
            self.loadOwnKey(filename)
            self.logger.info('Using existing keypair from `%s`', self.keyfile)
        except self.KeyNotFoundException:
            self.logger.info('Generating a new keypair...')
            from time import time
            t = time()
            self.generateOwnKey(filename)
            self.logger.debug('    ...took %.2f second(s)', time() - t)
            self.logger.info('Key saved to `%s`', self.keyfile)

    def _saveKeyFile(self, key, filename):
        with open(filename, 'w') as fp:
            fp.write(key.exportKey('PEM'))

    def _loadKeyData(self, data):
        return RSA.importKey(data)

    def _loadKeyFile(self, filename):
        with open(filename, 'r') as fp:
            key = self._loadKeyData(fp.read())
        return key

    def loadOwnKey(self, filename=None):
        # load private key
        self.keyfile = filename or C_KEY_FILENAME
        if not self.keyfile:
            raise self.KeyNotFoundException('Could not find key to load')
        self.privatekey = self._loadKeyFile(self.keyfile)
        self.publickey = self.privatekey.publickey()

    def generateOwnKey(self, filename=None):
        self.privatekey = RSA.generate(C_KEY_BITS)
        self.publickey = self.privatekey.publickey()
        # default key filenane
        self.keyfile = filename or C_KEY_FILENAME
        # write private key
        self._saveKeyFile(self.privatekey, self.keyfile)


    class KeyNotFoundException(Exception):
        """
        The specified key could not be found.
        """
        pass