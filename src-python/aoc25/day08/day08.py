import logging
import sys

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xyz
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    40
    """
    coords = [Xyz.parse(line) for line in lines]

    circuits: list[set] = []





    return sum(sorted(map(len, circuits), reverse=True)[0:3])


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))

    """
    for line in lines:
        pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=None)
    timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=None)
