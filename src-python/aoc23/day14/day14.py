import logging

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Direction, NORTH, SOUTH, WEST, EAST
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
    return _tilt_dish(grid, NORTH)
    # return _count_weight(grid)


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    64
    """
    # collect samples to find repeating pattern
    sample_grid = Grid(lines)
    samples = []
    for i in range(200):
        load = _rotate_dish(sample_grid)
        samples.append(load)

    # detect repeating sequence
    seq_start, seq_size = find_repeating_sequence(samples, PATTERN_SIZE, confidence=2)

    correct_sample_index = seq_start + ((1000000000 - seq_start) % seq_size) - 1
    return samples[correct_sample_index]


def _rotate_dish(grid):
    load = 0
    for d in [NORTH, WEST, SOUTH, EAST]:
        load = _tilt_dish(grid, d)
    return load


def _tilt_dish(grid, direction: Direction):
    load = 0
    for bi in range(grid.width):
        block = grid.cols[bi] if direction in (NORTH, SOUTH) else grid.rows[bi]
        free_index = 0
        if direction in (SOUTH, EAST):
            block = tuple(reversed(block))
        for i, cell in enumerate(block):
            if cell.value == "O":
                if free_index < i:
                    cell.value = "."
                    block[free_index].value = "O"
                load += grid.height - block[free_index].pos.y
                free_index += 1
            elif cell.value == "#":
                free_index = i + 1
    # log.debug(grid)
    return load


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
