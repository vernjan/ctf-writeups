# Van keys

Hi, packet inspector,

all our delivery vans use password instead of standard car keys. Today, we have found out that the AI has implemented a
new security measure – the vans are now referred as "AES Vans" and the password has been changed and encrypted. The
decryption part is not yet finished, so we can't start any delivery van since morning!

Good news is that we managed to get the latest version of the decryption script from git repository. Bad news is that
the script is not finished yet! Your task is to the finalize the script and decrypt the password as soon as possible.

Download [the script and encrypted password] (MD5 checksum `e67c86a277b0d8001ea5b3e8f6eb6868`).

May the Packet be with you!

---

What is required to make the script work:

- fix syntax errors (missing double colons)
- download `pi_dec_1m.txt` from internet (Pi 1 million decimals)
- add missing imports
  ```python
  import base64
  import hashlib
  import random
  ```
- finish `main` implementation:
  ```python
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
  ```
  
Run the script:
```
Mysterious Delivery, Ltd. - ultimate van engine secure start
FLAG{ITRD-Pyuv-JuLt-9zpM}
```