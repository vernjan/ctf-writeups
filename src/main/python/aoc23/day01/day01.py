import logging

from sortedcontainers import SortedDict

from util.data_io import read_input, timed_run, read_test_input
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    142
    """
    return sum_digits(lines, patterns="1 2 3 4 5 6 7 8 9".split())


def star2(lines: list[str], ):
    """
    >>> star2(read_test_input(__file__, "input-test2.txt"))
    281
    """

    return sum_digits(lines, patterns="one two three four five six seven eight nine 1 2 3 4 5 6 7 8 9".split())


def sum_digits(lines, patterns: list[str]):
    def convert_digit(digit: str):
        return digit if digit.isdigit() else str(patterns.index(digit) + 1)

    total = 0
    for line in lines:
        matches = SortedDict()
        for p in patterns:
            if p in line:
                matches[line.index(p)] = p
                matches[line.rindex(p)] = p
        sorted_values = matches.values()
        total += int(convert_digit(sorted_values[0]) + convert_digit(sorted_values[-1]))
    return total


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 55029
    # Star 2: 55686
