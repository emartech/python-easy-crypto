from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from base64 import b64decode

from key import Key

class Crypto:

    PASSWORD_SALT_SIZE = 12
    IV_SIZE = 12
    AUTH_TAG_SIZE = 16

    @classmethod
    def decrypt(cls, password, ciphertext):
        cls._validate_ciphertext_length(ciphertext)
        key = cls._key_from_cipher(password, ciphertext)
        return cls._decrypt_with_key(key, ciphertext)

    # private
    @classmethod
    def _decrypt_with_key(cls, key, ciphertext):
        aesgcm = AESGCM(key)
        iv = cls._iv_from_cipher(ciphertext)
        encrypted_payload = cls._encrypted_payload_from_cipher(ciphertext)
        return aesgcm.decrypt(iv, encrypted_payload, None)

    @classmethod
    def _key_from_cipher(cls, password, ciphertext):
        salt = cls._salt_from_cipher(ciphertext)
        return Key.generate_with_salt(password, salt)

    @classmethod
    def _salt_from_cipher(cls, ciphertext):
        decoded_ciphertext = b64decode(ciphertext)
        return decoded_ciphertext[0:cls.PASSWORD_SALT_SIZE]

    @classmethod
    def _iv_from_cipher(cls, ciphertext):
        decoded_ciphertext = b64decode(ciphertext)
        return decoded_ciphertext[cls.PASSWORD_SALT_SIZE:cls.PASSWORD_SALT_SIZE + cls.IV_SIZE]

    @classmethod
    def _encrypted_payload_from_cipher(cls, ciphertext):
        decoded_ciphertext = b64decode(ciphertext)
        return decoded_ciphertext[cls.PASSWORD_SALT_SIZE + cls.IV_SIZE:]

    @classmethod
    def _validate_ciphertext_length(cls, ciphertext):
        min_required_ciphertext_length = cls.PASSWORD_SALT_SIZE + cls.IV_SIZE + cls.AUTH_TAG_SIZE + 1
        if len(ciphertext) < min_required_ciphertext_length :
            raise ValueError('Ciphertext must be at least ' + str(min_required_ciphertext_length) + ' bytes long.')
