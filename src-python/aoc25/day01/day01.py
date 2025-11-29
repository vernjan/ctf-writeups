import logging

from util.data_io import read_input, timed_run, read_test_input
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    ???
    """
    return 0


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    ???
    """
    return 0


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: ???
    # Star 2: ???
