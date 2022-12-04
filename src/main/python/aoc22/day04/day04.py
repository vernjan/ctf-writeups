from data_input import read_all_lines

def star1():
    total = 0
    for line in read_all_lines("input.txt"):
        el1, el2 = line.split(",")
        el1_lower, el1_upper = parse_pair(el1)
        el2_lower, el2_upper = parse_pair(el2)
        if (el1_lower <= el2_lower and el1_upper >= el2_upper) or (el2_lower <= el1_lower and el2_upper >= el1_upper):
            total += 1
            print(line)
        # elif el2_lower <= el1_lower and el2_upper >= el1_upper:
        #     total += 1
        #     print(line)
    return total

def star2():
    total = 0
    for line in read_all_lines("input.txt"):
        el1, el2 = line.split(",")
        el1_lower, el1_upper = parse_pair(el1)
        el2_lower, el2_upper = parse_pair(el2)
        if not ((el1_upper < el2_lower) or (el2_upper < el1_lower)):
            total += 1
            print(line)
    return total

def parse_pair(el1):
    return [int(n) for n in el1.split("-")]


print(star1())
print(star2())
