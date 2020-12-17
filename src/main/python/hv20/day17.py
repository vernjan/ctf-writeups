import jwt

f = open("key.pub", "r")
key = f.read()

payload = {
    "exp": 1609229515,
    "iat": 1608225915,
    "sub": "santa1337"
}

encoded_jwt = jwt.encode(payload, key, algorithm='HS256', headers={'kid': '1d21a9f945'})
print(encoded_jwt)

