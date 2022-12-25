import logging
from typing import List

from util.data_io import read_input, read_test_input, timed_run
from util.ds.grid import Grid
from util.log import log


def star1(lines: List[str], padding_size):
    """
    >>> star1(read_test_input(__file__), 3)
    110
    """

    grid = Grid(lines, padding_size)
    log.debug(grid)

    elves = grid.find_all("#")

    return _count_empty(elves, grid)


def star2(lines: List[str], padding_size):
    """
    >>> star2(read_test_input(__file__))

    """

    pass


def _count_empty(elves, grid):
    min_x, min_y = grid.width, grid.height
    max_x, max_y = 0, 0
    for cell in grid.get_all_cells():
        if cell.value == "#":
            min_x = min(min_x, cell.pos.x)
            min_y = min(min_y, cell.pos.y)
            max_x = max(max_x, cell.pos.x)
            max_y = max(max_y, cell.pos.y)
    return (max_x - min_x + 1) * (max_y - min_y + 1) - len(elves)


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__), 10))
    timed_run("Star 2", lambda: star2(read_input(__file__), 10))

    # Star 1:
    # Star 2:
