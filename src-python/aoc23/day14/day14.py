import logging

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xy, Direction, NORTH, SOUTH, WEST, EAST
from util.ds.grid import Grid
from util.functions import find_repeating_sequence
from util.log import log

SAMPLE_COUNT = 500
PATTERN_SIZE = 5


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    136
    """

    grid = Grid(lines)
    _tilt_dish(grid, NORTH)
    return _count_weight(grid)


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    64
    """
    # collect samples to find repeating pattern
    sample_grid = Grid(lines)
    samples = []
    for i in range(SAMPLE_COUNT):
        _rotate_dish(sample_grid)
        weight = _count_weight(sample_grid)
        samples.append(weight)

    # detect repeating sequence
    seq_start, seq_size = find_repeating_sequence(samples, PATTERN_SIZE)

    total_reps = seq_start + ((1000000000 - seq_start) % seq_size)
    grid = Grid(lines)
    for i in range(total_reps):
        _rotate_dish(grid)
    return _count_weight(grid)


def _rotate_dish(grid):
    for d in [NORTH, WEST, SOUTH, EAST]:
        _tilt_dish(grid, d)


def _tilt_dish(grid, direction: Direction):
    for bi in range(grid.width):
        block = grid.get_col_values(bi) if direction in (NORTH, SOUTH) else grid.get_row_values(bi)
        free_index = 0
        if direction in (SOUTH, EAST):
            block.reverse()  # makes indexing easier
        for i, val in enumerate(block):
            if val == "O":
                if free_index < i:
                    block[free_index] = "O"
                    block[i] = "."
                free_index += 1
            elif val == "#":
                free_index = i + 1

        if direction in (SOUTH, EAST):
            block.reverse()
        for i, val in enumerate(block):
            pos = Xy(bi, i) if direction in (NORTH, SOUTH) else Xy(i, bi)
            grid.set_value(pos, val)


def _count_weight(grid):
    total = 0
    for cell in grid.get_all_cells():
        if cell.value == "O":
            total += grid.height - cell.pos.y
    return total


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 108826
    # Star 2: 99291
