import logging

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    114
    """
    total = 0
    for line in lines:
        all_zeroes = False
        numbers = list(map(int, line.split()))
        last_numbers = []
        diffs = []
        while not all_zeroes:
            all_zeroes = True
            for i in range(1, len(numbers)):
                diff = numbers[i] - numbers[i - 1]
                diffs.append(diff)
                all_zeroes &= diff == 0
            last_numbers.append(numbers[-1])
            numbers = diffs
            diffs = []
        total += sum(last_numbers)
    return total


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    2
    """
    total = 0
    for line in lines:
        all_zeroes = False
        numbers = list(map(int, line.split()))
        first_numbers = []
        diffs = []
        while not all_zeroes:
            all_zeroes = True
            for i in range(1, len(numbers)):
                diff = numbers[i] - numbers[i - 1]
                diffs.append(diff)
                all_zeroes &= diff == 0
            first_numbers.append(numbers[0])
            numbers = diffs
            diffs = []
        subtotal = first_numbers[-1]
        for i in range(len(first_numbers) - 2, -1, -1):  # iterate backward, starting from second to last
            subtotal = first_numbers[i] - subtotal

        total += subtotal
    return total


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 2175229206
    # Star 2: 942
