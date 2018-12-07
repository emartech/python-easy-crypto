import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class Key:

    ITERATION_COUNT = 10000
    KEY_SIZE = 32

    @classmethod
    def generate(cls, password, password_salt_size):
        salt = os.urandom(password_salt_size)
        return cls.generate_with_salt(password, salt), salt

    @classmethod
    def generate_with_salt(cls, password, salt):
        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = cls.KEY_SIZE,
            salt = salt,
            iterations = cls.ITERATION_COUNT,
            backend = default_backend()
        )
        try:
            pwd_in_bytes = bytes(password, 'utf-8')
        except:
            pwd_in_bytes = bytes(password)
        return kdf.derive(pwd_in_bytes)
