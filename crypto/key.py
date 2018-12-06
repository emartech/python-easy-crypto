import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class Key:

    PASSWORD_SALT_SIZE = 12
    ITERATION_COUNT = 10000
    KEY_SIZE = 32

    @classmethod
    def generate(cls, password):
        salt = os.urandom(cls.PASSWORD_SALT_SIZE)
        return cls.generate_with_salt(password, salt)
    
    @classmethod
    def generate_with_salt(cls, password, salt):
        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = cls.KEY_SIZE,
            salt = salt,
            iterations = cls.ITERATION_COUNT,
            backend = default_backend()
        )
        return kdf.derive(password)
