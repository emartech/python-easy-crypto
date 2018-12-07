import unittest
import os

from easycrypto.key import Key

class KeyTest(unittest.TestCase):
    def test_key_length_is_as_specified(self):
        key, _ = Key.generate('pwd', 12)
        self.assertEqual(len(key), 32)

    def test_generate_uses_different_salt_every_time(self):
        self.assertNotEqual(
            Key.generate('weakpassword', 12),
            Key.generate('weakpassword', 12)
        )

    def test_generate_with_salt_is_deterministic(self):
        salt = os.urandom(12)
        self.assertEqual(
            Key.generate_with_salt('weakpassword', salt),
            Key.generate_with_salt('weakpassword', salt)
        )

    def test_generate_with_salt_uses_password(self):
        salt = os.urandom(12)
        self.assertNotEqual(
            Key.generate_with_salt('weakpassword', salt),
            Key.generate_with_salt('anotherpassword', salt)
        )
