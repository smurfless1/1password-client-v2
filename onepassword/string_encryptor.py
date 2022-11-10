import base64
from typing import Union

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 32  # Bytes


class StringEncryptor:
    def __init__(self, secret_key: Union[str, bytes]):
        if isinstance(secret_key, str):
            self.secret_key = str.encode(secret_key)[0:BLOCK_SIZE]
        else:
            self.secret_key = secret_key[0:BLOCK_SIZE]
        self.cipher = AES.new(self.secret_key, AES.MODE_ECB)

    def decode(self, encoded: bytes):
        return unpad(self.cipher.decrypt(base64.b64decode(encoded)), BLOCK_SIZE).decode('UTF-8')

    def encode(self, input_str: str):
        return base64.b64encode(self.cipher.encrypt(pad(str.encode(input_str), BLOCK_SIZE)))
