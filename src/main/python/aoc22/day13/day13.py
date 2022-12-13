import logging
from typing import List
from simple_logging import log

from data_input import read_all_lines


def star1(lines: List[str]):
    """
    >>> star1(read_all_lines("input-test.txt"))
    13
    """


    foo = [[[], 5, [10, 8, 8, [0, 2, 2, 3]], [[2, 0, 8, 9, 6], [10, 3, 4, 5], [3, 6, 1, 2, 2], [7, 3, 5, 7]],
            [[6, 6, 1], [9], 0]], [6, 8, 10, []], [[0], 9, 9, [[5, 4, 1, 9, 2], [7, 10]]], []]

    log.debug(foo)

    index_sum = 0

    line1 = None
    line2 = None
    for i, line in enumerate(lines):
        if i % 3 == 0:
            line1 = line
        elif i % 3 == 1:
            line2 = line
        else:

            brackets1 = _find_matching_brackets(line1)
            brackets2 = _find_matching_brackets(line2)
            # log.debug(f"Brackets 1: {brackets1}")
            # log.debug(f"Brackets 2: {brackets2}")
            if _signals_equal(line1, 0, -1, brackets1, line2, 0, -1, brackets2):
                index_sum += i

    return index_sum


def star2(lines: List[str]):
    """
    >>> star2(read_all_lines("input-test.txt"))
    'TODO'
    """

    pass


def _signals_equal(line1, from1, to1, brackets1, line2, from2, to2, brackets2):
    log.debug(f"Comparing {line1[from1, to1]} vs {line2[from2, to2]}")

    while from1 < to1 and from2 < to2:
        symbol1 = line1[from1]
        symbol2 = line2[from2]

        if symbol1 == "[" and symbol2 == "[":
            if _signals_equal(line1, from1 + 1, brackets1[from1] - 1, brackets1,
                              line2, from2 + 1, brackets2[from2] - 1, brackets2):
                from1 += brackets1[from1] + 1
                from2 += brackets2[from2] + 1

        if symbol1 == "[" or symbol2 == "[":
            pass

    return True


def _find_matching_brackets(line):
    stack = []
    brackets = {}
    for i, symbol in enumerate(line):
        if symbol == "[":
            stack.append(i)
        elif symbol == "]":
            opening_index = stack.pop()
            brackets[opening_index] = i
    return brackets


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    lines = read_all_lines("input.txt")
    print(f"Star 1: {star1(lines)}")
    print(f"Star 2: {star2(lines)}")

    # Star 1:
    # Star 2:
