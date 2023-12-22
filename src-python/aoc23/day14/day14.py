import logging

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Direction, NORTH, SOUTH, WEST, EAST
from util.ds.grid import Grid
from util.functions import find_rsequence
from util.log import log

SAMPLE_COUNT = 200
PATTERN_SIZE = 5


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    136
    """

    grid = Grid(lines)
    return _tilt_dish(grid, NORTH)


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    64
    """
    # collect samples to find repeating pattern
    sample_grid = Grid(lines)
    samples = []
    for i in range(SAMPLE_COUNT):
        load = _rotate_dish(sample_grid)
        samples.append(load)

    # detect repeating sequence
    rseq = find_rsequence(samples, PATTERN_SIZE, confidence=2)

    correct_sample_index = rseq.first_index + ((1000000000 - rseq.first_index) % rseq.rsize) - 1
    return samples[correct_sample_index]


def _rotate_dish(grid):
    for d in [NORTH, WEST, SOUTH, EAST]:
        load = _tilt_dish(grid, d, calc_load=(d == EAST))
    return load


def _tilt_dish(grid, direction: Direction, calc_load=True) -> int:
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
                if calc_load:
                    load += grid.height - block[free_index].pos.y
                free_index += 1
            elif cell.value == "#":
                free_index = i + 1
    return load


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 108826
    # Star 2: 99291
