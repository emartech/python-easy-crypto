import unittest
import os

from crypto.crypto import Crypto

class CryptoTest(unittest.TestCase):
    def test_decrypt_fails_if_ciphertext_too_short(self):
        try:
            Crypto.decrypt('password', os.urandom(40))
            self.fail("decrpyt did not raise error")
        except ValueError, e:
            self.assertEquals("Ciphertext must be at least 41 bytes long.", e.message)

    def test_decrypt_sample(self):
        data = Crypto.decrypt('myweakpassword', 'IuXiWhFZjWew8XM7R/xNXEuN8nyoB3sVrjbj1pMokFQe1Q0l32RpwbFuemPcllaRmOr8UZcaMHs=')
        self.assertEqual(data, 'littlesecretdata')
