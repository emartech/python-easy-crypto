import unittest
import os

from crypto import Crypto

class CryptoTest(unittest.TestCase):
    def test_constructor_fails_if_passwordsaltsize_is_not_a_number(self):
        try:
            eCrypto = Crypto('not number', 10000)
            self.fail("constructor did not raise error")
        except TypeError, e:
            self.assertEquals( "password_salt_size must be a number", e.message )

    def test_constructor_fails_if_iteration_count_is_not_a_number(self):
        try:
            eCrypto = Crypto(12, 'not number')
            self.fail("constructor did not raise error")
        except TypeError, e:
            self.assertEquals( "iteration_count must be a number", e.message )

    def test_constructor_uses_defaults_if_params_not_specified(self):
        eCrypto = Crypto()
        self.assertEqual(eCrypto.password_salt_size, 12)
        self.assertEqual(eCrypto.iteration_count, 10000)

    def test_decrypt_fails_if_ciphertext_too_short(self):
        try:
            eCrypto = Crypto()
            eCrypto.decrypt('password', os.urandom(40))
            self.fail("decrpyt did not raise error")
        except ValueError, e:
            self.assertEquals("Ciphertext must be at least 41 bytes long.", e.message)

    def test_decrypt_sample(self):
        eCrypto = Crypto(12, 10000)
        data = eCrypto.decrypt('myweakpassword', 'IuXiWhFZjWew8XM7R/xNXEuN8nyoB3sVrjbj1pMokFQe1Q0l32RpwbFuemPcllaRmOr8UZcaMHs=')
        self.assertEqual(data, 'littlesecretdata')

if __name__ == '__main__':
    unittest.main()
