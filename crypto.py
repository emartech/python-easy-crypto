import os
import binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from base64 import b64decode

DEFAULT_PASSWORD_SALT_SIZE = 12
DEAFULT_ITERATION_COUNT = 10000
IV_SIZE = 12
KEY_SIZE = 32
AUTH_TAG_SIZE = 16

class Crypto:
    def __init__(self, password_salt_size = DEFAULT_PASSWORD_SALT_SIZE, iteration_count = DEAFULT_ITERATION_COUNT):
        self._validateInitializationParams(password_salt_size, iteration_count)
        self.password_salt_size = password_salt_size
        self.iteration_count = iteration_count

    def decrypt(self, password, ciphertext):
        self._validateCiphertextLength(ciphertext)
        key = self._keyFromCipher(password, ciphertext)
        return self._decryptWithKey(key, ciphertext)

    def _decryptWithKey(self, key, ciphertext):
        aesgcm = AESGCM(key)
        iv = self._ivFromCipher(ciphertext)
        encrypted_payload = self._encryptedPayloadFromCipher(ciphertext)
        return aesgcm.decrypt(iv, encrypted_payload, None)

    def _keyFromCipher(self, password, ciphertext):
        salt = self._saltFromCipher(ciphertext)
        return self._keyFromSalt(password, salt)

    def _keyFromSalt(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = KEY_SIZE,
            salt = salt,
            iterations = self.iteration_count,
            backend = default_backend()
        )
        return kdf.derive(password)

    def _saltFromCipher(self, ciphertext):
        decoded_ciphertext = b64decode(ciphertext)
        return decoded_ciphertext[0:self.password_salt_size]

    def _ivFromCipher(self, ciphertext):
        decoded_ciphertext = b64decode(ciphertext)
        return decoded_ciphertext[self.password_salt_size:self.password_salt_size + IV_SIZE]

    def _encryptedPayloadFromCipher(self, ciphertext):
        decoded_ciphertext = b64decode(ciphertext)
        return decoded_ciphertext[self.password_salt_size + IV_SIZE:]

    def _validateCiphertextLength(self, ciphertext):
        min_required_ciphertext_length = self.password_salt_size + IV_SIZE + AUTH_TAG_SIZE + 1
        if len(ciphertext) < min_required_ciphertext_length :
            raise ValueError('Ciphertext must be at least ' + str(min_required_ciphertext_length) + ' bytes long.')

    def _validateInitializationParams(self, password_salt_size, iteration_count):
        if type(password_salt_size) is not int:
            raise TypeError('password_salt_size must be a number')
        if type(iteration_count) is not int:
            raise TypeError('iteration_count must be a number')
