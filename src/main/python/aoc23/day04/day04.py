import logging
from collections import defaultdict

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    13
    """
    return solve(lines)[0]


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    30
    """
    return solve(lines)[1]


def solve(lines: list[str]):
    total_star1 = 0
    total_star2 = 0
    card_copies = defaultdict(lambda: 1)  # star 2
    for card_id, line in enumerate(lines):
        card_copies_cnt = card_copies[card_id]
        win_numbers, my_numbers = [set(numbers.split()) for numbers in line.split(":")[1].split("|")]
        matching_numbers = len(win_numbers.intersection(my_numbers))
        card_value = 0 if matching_numbers == 0 else 2 ** (matching_numbers - 1)
        total_star1 += card_value
        # star 2: create copies
        for i in range(min(matching_numbers, len(lines) - card_id - 1)):
            card_copies[card_id + i + 1] += card_copies_cnt
        total_star2 += card_copies_cnt
    return total_star1, total_star2


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 21959
    # Star 2: 5132675
