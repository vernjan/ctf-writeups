import logging
from collections import defaultdict
from typing import List, Tuple, Set, Dict

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import EAST, SOUTH, NORTH, WEST, Xy, Direction
from util.ds.grid import Grid, GridCell
from util.log import log

BEAM = Tuple[GridCell[str], Direction]

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
    mirror_cache = defaultdict(list)
    _solve(grid, start_cell, EAST, mirror_cache)
    return _solve(grid, start_cell, EAST, mirror_cache)


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    51
    """

    grid = Grid(lines)
    best = 0
    mirror_cache: Dict[BEAM, List[BEAM]] = defaultdict(list)
    for start_cell in grid.cols[0]:
        best = max(best, _solve(grid, start_cell, EAST, mirror_cache))
    for start_cell in grid.cols[-1]:
        best = max(best, _solve(grid, start_cell, WEST, mirror_cache))
    for start_cell in grid.rows[0]:
        best = max(best, _solve(grid, start_cell, SOUTH, mirror_cache))
    for start_cell in grid.rows[-1]:
        best = max(best, _solve(grid, start_cell, NORTH, mirror_cache))
    return best


def _solve(grid, start_cell, start_dir, mirror_cache: Dict[BEAM, List[BEAM]]):
    visited: Set[BEAM] = set()
    beams: List[BEAM] = [(start_cell, start_dir)]
    last_mirror = None
    while beams:
        beam = beams.pop()
        if beam in visited:
            continue
        visited.add(beam)

        beam_cell, beam_dir = beam
        beam_value, beam_pos = beam_cell.value, beam_cell.pos

        # TODO cache -| otherwise it has small performance impact
        next_mirrors = mirror_cache[beam]
        if next_mirrors:
            assert len(next_mirrors) == 1, "Only one mirror expected now"
            for next_mirror in next_mirrors:
                next_mirrors_pos = next_mirror[0].pos
                next_mirror_dir = next_mirror[1]
                jumped_cells = list((cell, next_mirror_dir) for cell in
                                    grid.get_cells_between(beam_pos, next_mirrors_pos))[1:-1]
                visited.update(jumped_cells)
                beams.append(next_mirror)
            last_mirror = None
            continue

        if beam_value in "-|":
            last_mirror = None

        if beam_value in "\\/":
            if last_mirror:
                mirror_cache[last_mirror].append(beam)
            last_mirror = beam

        next_dirs = TILE_MOVES[beam_value].get(beam_dir, [beam_dir])
        for next_dir in next_dirs:
            next_pos = beam_pos.neighbor(next_dir)
            if grid.has(next_pos):
                beams.append((grid.get_cell(next_pos), next_dir))
            else:
                last_mirror = None

    return len({cell[0].pos for cell in visited})


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 8112
    # Star 2: 8314
