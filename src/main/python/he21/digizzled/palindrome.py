from itertools import product
import string

p = product(string.ascii_lowercase, repeat=5)

for i in list(p):
    p = ''.join(i)
    print(p[0:-1] + p[::-1])



