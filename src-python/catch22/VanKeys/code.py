"""
The Mysterious Delivery, Ltd.
"""

__author__ = "Mysterious AI"
__version__ = "3.14"

import base64
import hashlib
import random

from Crypto import Random
from Crypto.Cipher import AES


class AESCipher():
    """
    AES
    """

    def __init__(self, key):
        """
        constructor
        """
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        """
        Decrypt function
        """
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        """
        Decrypt function
        """
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]


def generate_van_key(keylen):
    """
    Generate super-secure key for AES Vans
    """
    data = ''
    with open('pi_dec_1m.txt', 'r') as fhnd:
        data = fhnd.read()
    random.seed(314)
    key = '3.14'
    for i in range(0, keylen - len(key)):
        key += data[random.randint(0, 999999)]
    return key


def main():
    """
    main
    """
    print("Mysterious Delivery, Ltd. - ultimate van engine secure start")

    # generate key
    key = generate_van_key(128)

    # decryption
    aes = AESCipher(key)

    with open('van_keys_enc.aes', 'r') as f:
        enc = f.read()
        print(aes.decrypt(enc))



main()

# EOF
