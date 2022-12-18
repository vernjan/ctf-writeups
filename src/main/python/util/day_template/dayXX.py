import logging
from typing import List

from util.io import read_all_lines, timed_run
from util.logging import log


def star1(lines: List[str]):
    """
    >>> star1(read_all_lines(__file__, "input-test.txt"))

    """

    pass


def star2(lines: List[str]):
    """
    >>> star2(read_all_lines(__file__, "input-test.txt"))

    """

    pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    lines = read_all_lines(__file__, "input.txt")
    timed_run("Star 1", lambda: star1(lines))
    timed_run("Star 2", lambda: star2(lines))

    # Star 1:
    # Star 2:
