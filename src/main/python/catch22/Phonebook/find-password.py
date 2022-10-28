import hashlib

pw_orig = "TOOSTRONGPASS."
expected = "32644235283BC5561CC7FE4FFFADDAEE"


def permute(pw, pos):
    if len(pw) == pos:
        return

    if pw[pos].isalpha():
        pw_new = pw[0:pos] + pw[pos].lower() + pw[pos + 1:]
        # print(pw_new)

        guess = hashlib.new("md4", pw_new.encode("utf-16LE")).hexdigest().upper()

        if guess == expected:
            print("BINGO !!!")
            print(pw_new)
            exit(0)

        permute(pw, pos + 1)
        permute(pw_new, pos + 1)
    else:
        permute(pw, pos + 1)


permute(pw_orig, 0)
