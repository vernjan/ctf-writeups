import logging
from typing import List
from collections import deque
from util.functions import circular_shift

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


# TODO Move to functions - circular_shift
def star1(lines: List[str]):
    """
    >>> star1([1, 2, -3, 3, -2, 0, 4])
    3
    >>> star1([7, 8, -9, 3, -2, 0, 4])
    3
    """

    return _decrypt(lines, cipher_key=1, rounds=1)


def star2(lines: List[str]):
    """
    >>> star2(read_test_input(__file__))
    1623178306
    """

    return _decrypt(lines, cipher_key=811589153, rounds=10)


def _decrypt(lines: List[str], cipher_key: int, rounds: int) -> int:
    named_numbers = _preprocess_numbers(lines, cipher_key)
    decrypted_numbers = deque(named_numbers)

    for _ in range(rounds):
        for named_number in named_numbers:
            index = decrypted_numbers.index(named_number)
            number = named_number[0]
            circular_shift(decrypted_numbers, index, steps=number)

    log.debug(decrypted_numbers)

    total = 0
    zero_index = decrypted_numbers.index((0, 0))
    for offset in [1000, 2000, 3000]:
        index = (zero_index + offset) % len(named_numbers)
        number = decrypted_numbers[index][0]
        log.debug(f"Coordinate value: {number}")
        total += number

    return total


def _preprocess_numbers(lines, cipher_key):
    named_numbers = []
    counters = {}  # make the numbers unique
    for number in map(int, lines):
        if number not in counters:
            counters[number] = 0
        else:
            counters[number] += 1
        named_numbers.append((number * cipher_key, counters[number]))
    return named_numbers


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 18257
    # Star 2: 4148032160983
