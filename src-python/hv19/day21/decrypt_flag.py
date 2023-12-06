import base64
import hashlib

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC

encrypted_flag = 'Hy97Xwv97vpwGn21finVvZj5pK/BvBjscf6vffm1po0='

# Dictionary with ~14 millions passwords
f = open('d:\\temp\\rockyou.txt', 'r', errors='replace')

password = f.readline()
while password:
    if len(password) != 17:  # +1 for line breaks
        password = f.readline()
        continue

    passwordBytes = bytes(password.rstrip('\n'), 'UTF-8')
    passwordSHA256 = SHA256.new(passwordBytes)
    d = int(passwordSHA256.hexdigest(), 16)

    try:
        # If the private key is not valid for the given public key (x and y) an exception is thrown
        key = ECC.construct(
            curve='P-256',
            d=d,
            point_x=0xc58966d17da18c7f019c881e187c608fcb5010ef36fba4a199e7b382a088072f,
            point_y=0xd91b949eaf992c464d3e0d09c45b173b121d53097a9d47c25220c0b4beb943c
        )
        print('The password is: ' + password)

        aesKey = hashlib.pbkdf2_hmac('sha256', passwordBytes, b'TwoHundredFiftySix', 256 * 256 * 256)
        print('The AES key is: ' + aesKey.hex())

        cipher = AES.new(aesKey, AES.MODE_ECB)
        flag = cipher.decrypt(base64.b64decode(encrypted_flag))
        print('The flag is: ' + flag.decode("UTF-8"))

        break
    except ValueError:
        password = f.readline()
