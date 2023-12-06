import logging
import math
from typing import List, Tuple

from util.data_io import timed_run
from util.log import log


def star1(puzzle_input: List[Tuple[int, int]]):
    """
    >>> star1([(7, 9), (15, 40), (30, 200)])
    288
    """
    total = 1
    for time, distance in puzzle_input:
        log.debug(f"Solving time: {time}, current record: {distance}")
        boundary = _find_boundary(distance, time)
        subtotal = (math.ceil((time / 2)) - boundary) * 2
        if time % 2 == 0:
            subtotal += 1
        log.debug(f"Solution is {subtotal}")
        total *= subtotal
    return total


def _find_boundary(distance, time):
    start_from = distance // time  # low hanging optimization
    for i in range(start_from, time):
        if i * (time - i) > distance:
            log.debug(f"Boundary found {i} -> {i * (time - i)}")
            return i


def star2(puzzle_input: Tuple[int, int]):
    """
    >>> star2((71530, 940200))
    71503
    """
    return star1([puzzle_input])


if __name__ == "__main__":
    log.setLevel(logging.INFO)

    timed_run("Star 1", lambda: star1([(62, 644), (73, 1023), (75, 1240), (65, 1023)]))
    timed_run("Star 2", lambda: star2((62737565, 644102312401023)))

    # Star 1: 393120
    # Star 2: 36872656
