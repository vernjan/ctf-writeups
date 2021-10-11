# Encrypted Archive

Hi Expert,

some confused archeaologist brings you encrypted zip file and some text string which should leads to password. Then points on it, muttered something about crazy times, and left. Prove your skill and get the password for file.

Download the file [encrypted_archive.zip](encrypted_archive.zip) (sha256 fingerprint: `8ee4319c2b54448bc28470262681f6151f37b8283697a41ec2c574c040e61174`).

---

The first challenge is easy. Unzip the archive and read `lead_to_password.txt` file.
It contains `8fd2011515522f6879dddd55d18a83d7`. This looks like a _md5_ hash.
Paste it into Google and find the original string/password - it is `mytreasure`.
Unzip the second archive `treasure_map.zip` and read `treasure_map.md`:

```
# Treasure map

1. Go to the temple of God #42
2. Find the south gate
3. Go to the south-west for 3 days and 3 night at constant speed 5 mph
4. Find closed cave entrance
5. Just right from cave entrance is letter-pannel
6. Enter code `FLAG{q5hi-Pa72-dxbp-wRHf}`
7. Profit
```