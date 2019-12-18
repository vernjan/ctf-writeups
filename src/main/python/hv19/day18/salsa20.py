from Crypto.Cipher import Salsa20

key = bytes.fromhex("0320634661B63CAFAA76C27EEA00B59BFB2F7097214FD04CB257AC2904EFEE46")
nonce = bytes.fromhex("11458FE7A8D032B1")
ciphertext = bytes.fromhex("096CD446EBC8E04D2FDE299BE44F322863F7A37C18763554EEE4C99C3FAD15")
cipher = Salsa20.new(key, nonce)
flag = cipher.decrypt(ciphertext)
print(flag)
