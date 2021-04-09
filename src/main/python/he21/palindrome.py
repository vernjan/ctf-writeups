from itertools import product
import string

passwords = product(string.ascii_lowercase, repeat=5)

for password in passwords:
    password = ''.join(password)
    print(password + password[1::-1])
