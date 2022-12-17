import logging
from typing import List

from data_input import read_all_lines, run
from simple_logging import log


def star1(lines: List[str]):
    """
    >>> star1(read_all_lines("input-test.txt"))
    'TODO'
    """

    pass


def star2(lines: List[str]):
    """
    >>> star2(read_all_lines("input-test.txt"))
    'TODO'
    """

    pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    lines = read_all_lines("input.txt")
    run("Star 1", lambda: star1(lines))
    run("Star 2", lambda: star1(lines))

    # Star 1:
    # Star 2:
