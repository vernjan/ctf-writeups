import logging
import re
from collections import defaultdict

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    13
    """
    total = 0
    for line in lines:
        game_id = int(re.findall(r"Card\s+(\d+):", line)[0])
        win, my = line.split(":")[1].split("|")
        win_numbers = set(win.split())
        log.debug(f"win_numbers: {win_numbers}")
        my_numbers = set(my.split())
        log.debug(f"my_numbers: {my_numbers}")
        card_value = 0
        for mn in my_numbers:
            if mn in win_numbers:
                card_value = 1 if card_value == 0 else card_value * 2
        total += card_value
    return total


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    30
    """
    total_copies = 0
    card_copies = defaultdict(lambda: 1)
    for line in lines:
        game_id = int(re.findall(r"Card\s+(\d+):", line)[0])
        card_copy_cnt = card_copies[game_id]
        log.debug(f"game_id: {game_id}, card_copies_cnt: {card_copy_cnt}")
        win, my = line.split(":")[1].split("|")
        win_numbers = set(win.split())
        log.debug(f"win_numbers: {win_numbers}")
        my_numbers = set(my.split())
        log.debug(f"my_numbers: {my_numbers}")
        card_value = 0
        for mn in my_numbers:
            if mn in win_numbers:
                card_value = 1 if card_value == 0 else card_value * 2
        log.debug(f"card_value: {card_value}")
        last = min(card_value, len(lines) - game_id - 1)
        for i in range(last):
            card_copies[game_id + i + 1] += card_copy_cnt
        total_copies += card_copy_cnt
        log.debug(card_copies)
    return total_copies


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    # timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1:
    # Star 2:
