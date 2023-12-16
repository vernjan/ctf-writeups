import logging
from typing import List, Tuple

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import EAST, Xy, SOUTH, NORTH, WEST, Direction
from util.ds.grid import Grid, GridCell
from util.log import log

BEAM_TYPE = Tuple[GridCell[str], Direction]

TILE_MOVES = {
    ".": {},
    "\\": {
        NORTH: [WEST],
        EAST: [SOUTH],
        SOUTH: [EAST],
        WEST: [NORTH],
    },
    "/": {
        NORTH: [EAST],
        EAST: [NORTH],
        SOUTH: [WEST],
        WEST: [SOUTH],
    },
    "-": {
        NORTH: [EAST, WEST],
        SOUTH: [EAST, WEST],
    },
    "|": {
        EAST: [NORTH, SOUTH],
        WEST: [NORTH, SOUTH],
    },
}


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    46
    """
    grid = Grid(lines)
    start_cell = grid.get_cell(Xy(0, 0))
    return _solve(grid, start_cell, EAST)


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    51
    """

    grid = Grid(lines)
    best = 0
    for start_cell in grid.cols[0]:
        best = max(best, _solve(grid, start_cell, EAST))
    for start_cell in grid.cols[-1]:
        best = max(best, _solve(grid, start_cell, WEST))
    for start_cell in grid.rows[0]:
        best = max(best, _solve(grid, start_cell, SOUTH))
    for start_cell in grid.rows[-1]:
        best = max(best, _solve(grid, start_cell, NORTH))
    return best


def _solve(grid, start_cell, start_dir):
    visited = set()
    beams: List[BEAM_TYPE] = [(start_cell, start_dir)]
    while beams:
        beam = beams.pop(0)
        if beam in visited:
            continue

        visited.add(beam)
        beam_cell, beam_dir = beam
        beam_value, beam_pos = beam_cell.value, beam_cell.pos

        next_dirs = TILE_MOVES[beam_value].get(beam_dir, [beam_dir])
        for next_dir in next_dirs:
            next_pos = beam_pos.neighbor(next_dir)
            if grid.has(next_pos):
                beams.append((grid.get_cell(next_pos), next_dir))

    return len({cell[0].pos for cell in visited})


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 8112
    # Star 2: 8314
