import unittest
from unittest_data_provider import data_provider
import os
from base64 import b64encode
from cryptography.exceptions import InvalidTag

from easycrypto.crypto import Crypto

class CryptoTest(unittest.TestCase):
    def test_decrypt_fails_if_ciphertext_too_short(self):
        with self.assertRaises(ValueError) as context:
            Crypto.decrypt('password', b64encode(os.urandom(40)))

        self.assertEqual('Ciphertext must be at least 41 bytes long.', str(context.exception))

    def test_decrypt_fails_if_wrong_password(self):
        with self.assertRaises(InvalidTag):
            Crypto.decrypt('wrongpassword', 'IuXiWhFZjWew8XM7R/xNXEuN8nyoB3sVrjbj1pMokFQe1Q0l32RpwbFuemPcllaRmOr8UZcaMHs=')

    tampered_ciphertexts = lambda: (
        ('SALTSALTSALT' + '8XM7R/xNXEuN' + '8nyoB3sVrjbj1pMokFQe1Q0l32RpwbFuemPc' + 'llaRmOr8UZcaMHs=', 'wrong salt'),
        ('IuXiWhFZjWew' + 'IVIVIVIVIVIV' + '8nyoB3sVrjbj1pMokFQe1Q0l32RpwbFuemPc' + 'llaRmOr8UZcaMHs=', 'wrong iv'),
        ('IuXiWhFZjWew' + '8XM7R/xNXEuN' + 'PAYLOADPAYLOADPAYLOADPAYLOADPAYLOADP' + 'llaRmOr8UZcaMHs=', 'wrong payload'),
        ('IuXiWhFZjWew' + '8XM7R/xNXEuN' + '8nyoB3sVrjbj1pMokFQe1Q0l32RpwbFuemPc' + 'AUTHAUTHAUTHAUTH', 'wrong auth tag'),
    )

    @data_provider(tampered_ciphertexts)
    def test_decrypt_fails_if_ciphertext_is_tampered_with(self, tampered_ciphertext, desc):
        with self.assertRaises(InvalidTag):
            Crypto.decrypt('myweakpassword', tampered_ciphertext)

    def test_decrypt_fails_if_ciphertext_is_not_b64encoded(self):
        with self.assertRaises(TypeError) as context:
            Crypto.decrypt('pwd', 'not a base 64 encoded string')
        self.assertEqual('Ciphertext must be a base64 encoded string.', str(context.exception))

    def test_decrypt_sample(self):
        data = Crypto.decrypt('myweakpassword', 'IuXiWhFZjWew8XM7R/xNXEuN8nyoB3sVrjbj1pMokFQe1Q0l32RpwbFuemPcllaRmOr8UZcaMHs=')
        self.assertEqual(data, 'littlesecretdata')

    def test_encrypt_returns_different_cipher_with_same_pwd_and_plaintext(self):
        self.assertNotEqual(
            Crypto.encrypt('pwd', 'secretdata'),
            Crypto.encrypt('pwd', 'secretdata')
        )

    def test_decryption_of_encrypted_data_returns_data(self):
        plaintext = 'mysecretdata'
        password = 'mypassword'
        self.assertEqual(plaintext, Crypto.decrypt(password, Crypto.encrypt(password, plaintext)))
