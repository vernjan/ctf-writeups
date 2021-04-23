from mnemonic import Mnemonic

mnemo = Mnemonic("english")

words = ["adapt", "bind", "bless", "blind", "civil", "craft", "garage", "good", "half", "hip", "home", "hotel",
          "lonely", "magnet", "metal", "mushroom", "napkin", "reason", "rescue", "ring", "shift", "small", "sunset",
          "tongue"]

# words = mnemo.generate(strength=256)
# print(words)

seed = mnemo.to_seed(' '.join(words), passphrase="")
print(seed)
print(bytes(seed).hex())

# entropy = mnemo.to_entropy(mylist)
# print(entropy)
