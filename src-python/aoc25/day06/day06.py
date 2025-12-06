import logging
import re
from functools import reduce

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    4277556
    """
    numbers = _parse_numbers(lines)

    total = 0
    for col, op in enumerate(lines[-1].split()):
        if op == '+':
            total += sum(numbers[col])
        else:
            total += reduce(lambda a, b: a * b, numbers[col])
    return total


def _parse_numbers(lines: list[str]) -> list[list[int]]:
    numbers: list[list[int]] = []
    for line in lines[:-1]:
        for col, number in enumerate(line.split()):
            if len(numbers) <= col:
                numbers.append([])
            numbers[col].append(int(number.strip()))
    return numbers


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    3263827
    """
    # make sure all lines have correct trailing spaces (IDE likes to remove them)
    max_line_length = max(map(len, lines))
    lines = [line + " " * (max_line_length - len(line)) for line in lines]

    total = 0

    op_line = lines[-1]
    op_indexes = list(map(lambda m: m.start(), re.finditer("[+*]", op_line)))
    for i, op_index in enumerate(op_indexes):
        start = op_index
        end = op_indexes[i + 1] if i < len(op_indexes) - 1 else max_line_length + 1

        numbers: list[int] = []
        for coli in range(start, end - 1):
            number = ""
            for rowi in range(len(lines) - 1):
                digit = lines[rowi][coli]
                if digit != ' ':
                    number += digit
            numbers.append(int(number))
        log.debug(numbers)

        op = op_line[op_index]
        if op == '+':
            total += sum(numbers)
        else:
            total += reduce(lambda a, b: a * b, numbers)

    return total


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=6757749566978)
    timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=None)
