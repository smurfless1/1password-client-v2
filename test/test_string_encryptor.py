import platform
import unittest
from functools import cached_property

from onepassword.string_encryptor import StringEncryptor


class StringEncrpytorTestCase(unittest.TestCase):
    @cached_property
    def encryptor(self):
        return StringEncryptor(str.encode(f"{platform.node():>32}"[:32]))

    def test_basics(self):
        dabytes = self.encryptor.encode("bob")
        decoded = self.encryptor.decode(dabytes)
        self.assertEqual("bob", decoded)


if __name__ == '__main__':
    unittest.main()
