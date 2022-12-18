from util.io import read_all_lines


def letter_priority(letter):
    if letter.islower():
        return ord(letter) - ord("`")
    if letter.isupper():
        return ord(letter) - ord("&")


def star1():
    total = 0
    for line in read_all_lines(__file__, "input.txt"):
        half = len(line) // 2
        p1, p2 = set(line[:half]), line[half:]

        for l in p2:
            if l in p1:
                total += letter_priority(l)
                break
    return total


def star2():
    total = 0
    counter = 1
    groups = []
    for line in read_all_lines("input.txt"):
        groups.append(set(line))
        if counter % 3 == 0:
            g1, g2, g3 = groups
            for l in g1:
                if l in g2 and l in g3:
                    total += letter_priority(l)

            groups = []

        counter += 1
    return total


if __name__ == "__main__":
    print(f"Star 1: {star1()}")
    print(f"Star 2: {star2()}")

# Star 1: 7737
# Star 2: 2697
