from mnemonic import Mnemonic

mnemo = Mnemonic("english")

words = ["adapt", "bind", "bless", "blind", "civil", "craft", "garage", "good", "half", "hip", "home", "hotel",
          "lonely", "magnet", "metal", "mushroom", "napkin", "reason", "rescue", "ring", "shift", "small", "sunset",
          "tongue"]

entropy = mnemo.to_entropy(words)
print(entropy)
