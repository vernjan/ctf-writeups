import logging
from typing import List

from util.data_io import read_input, read_test_input, timed_run
from util.ds.grid import Grid
from util.log import log


def star1(lines: List[str], padding_size):
    """
    >>> star1(read_test_input(__file__), 3)

    """

    grid = Grid(lines, padding_size)
    log.debug(grid)

    pass


def star2(lines: List[str]):
    """
    >>> star2(read_test_input(__file__))

    """

    pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__), 10))
    timed_run("Star 2", lambda: star2(read_input(__file__), 10))

    # Star 1:
    # Star 2:
