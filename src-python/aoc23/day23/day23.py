import logging
from collections import defaultdict
from dataclasses import dataclass
from typing import Set

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xy, NORTH, EAST, SOUTH, WEST
from util.ds.grid import Grid
from util.log import log


@dataclass(frozen=True)
class SearchCtx:
    head: Xy
    visited: Set[Xy]


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    94
    """

    slopes = {
        "^": NORTH,
        ">": EAST,
        "v": SOUTH,
        "<": WEST,
    }

    grid = Grid(lines)
    start_pos = grid.find_first(".")
    end_pos = grid.find_last(".")
    queue = [SearchCtx(start_pos, set())]
    longest_paths = defaultdict(int)
    while queue:
        ctx = queue.pop()
        if ctx.head == end_pos:
            log.debug(f"Found path with {len(ctx.visited)} steps, {ctx.head}")
            if len(ctx.visited) > longest_paths[ctx.head]:
                longest_paths[ctx.head] = len(ctx.visited)
        for direction, n in grid.get_neighbors(ctx.head, include_directions=True):
            n_cell = grid.get_cell(n)
            if n in ctx.visited:
                continue
            n_val = n_cell.value
            if n_val == "." or n_val in slopes and slopes[n_val] == direction:
                queue.append(SearchCtx(n, ctx.visited | {n}))

    return longest_paths[end_pos]


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))

    """
    for line in lines:
        pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 2070
    # Star 2:
