from data_input import read_all_lines

"""Symbols:
A - Rock
B - Paper
C - Scissors
"""

WIN_MOVES = {
    "A": "B",
    "B": "C",
    "C": "A"
}
LOST_MOVES = dict((v, k) for k, v in WIN_MOVES.items())  # invert the dict

score_part1 = 0
score_part2 = 0


def get_symbol_value(symbol):
    return ord(symbol) - ord("@")


def get_round_value():
    if me == op:
        return 3
    elif WIN_MOVES[op] == me:
        return 6
    else:
        return 0


def get_required_symbol(result):
    """A - Lost, B - Draw, C - Win"""
    if result == "A":
        return LOST_MOVES[op]
    if result == "B":
        return op
    if result == "C":
        return WIN_MOVES[op]


for line in read_all_lines("input.txt"):
    op = line[0]
    me = chr(ord(line[2]) - 23)  # shift XYZ to ABC

    score_part1 += get_symbol_value(me)
    score_part1 += get_round_value()

    me = get_required_symbol(me)
    score_part2 += get_symbol_value(me)
    score_part2 += get_round_value()

    round_value = 0

print(f"Star 1: {score_part1}")
print(f"Star 2: {score_part2}")

# Star 1: 11475
# Star 2: 16862
