import logging
import pprint
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Set, List, Dict

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xy, NORTH, EAST, SOUTH, WEST, Direction
from util.ds.grid import Grid
from util.log import log

SLOPES = {
    "^": NORTH,
    ">": EAST,
    "v": SOUTH,
    "<": WEST,
}


# (1,0):    {south: (1,0)->(3,5)},
# (3,5):    {south: (3,5)->(5,13),
#            east: (3,5)->(11,3)},
# (5,13):   {south: (5,13)->(13,19),
#            east: (5,13)->(13,13)},
# (11,3):   {south: (11,3)->(13,13),
#            east: (11,3)->(21,11)},
# (13,13):  {south: (13,13)->(13,19),
#            east: (13,13)->(21,11),
#            north: (13,13)->(11,3),
#            west: (13,13)->(5,13)},
# (13,19):  {east: (13,19)->(19,19),
#            north: (13,19)->(13,13),
#            west: (13,19)->(5,13)},
# (19,19):  {south: (19,19)->(21,22),
#            north: (19,19)->(21,11),
#            west: (19,19)->(13,19)},
# (21,11):  {south: (21,11)->(19,19),
#            north: (21,11)->(11,3),
#            west: (21,11)->(13,13)}


@dataclass(frozen=True)
class SearchCtx:
    head: Xy
    visited: Set[Xy] = field(default_factory=set)
    last_junction: Xy = None
    last_junction_dir: Direction = None
    last_junction_path: List[Xy] = field(default_factory=list)


@dataclass(frozen=True)
class JunctionPath:
    path: List[Xy]
    destination: Xy

    def __repr__(self):
        return f"{self.path[0]}->{self.destination}"


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    94
    """
    return _solve(lines, ".")


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    154
    """
    return _solve(lines, ".>v<^")


def _solve(lines, cond: str):
    grid = Grid(lines)
    junctions = _find_junctions(grid, cond)
    return _find_longest_path(grid, junctions)


def _find_junctions(grid: Grid, cond: str) -> Dict[Xy, Dict[Direction, JunctionPath]]:
    """
    >>> len(dict(_find_junctions(Grid(read_test_input(__file__)),".<>v^")))
    8
    """
    junctions: Dict[Xy, Dict[Direction, JunctionPath]] = defaultdict(dict)
    start_pos = grid.find_first(".")
    end_pos = grid.find_last(".")
    queue = [SearchCtx(start_pos)]
    while queue:
        ctx = queue.pop()
        is_junction_now = False
        if ctx.head in (start_pos, end_pos) or _is_junction(grid, ctx.head):
            is_junction_now = True
            if ctx.last_junction and ctx.last_junction_dir not in junctions[ctx.last_junction]:
                junctions[ctx.last_junction][ctx.last_junction_dir] = JunctionPath(ctx.last_junction_path, ctx.head)

        for direction, n in grid.get_neighbors(ctx.head, include_directions=True):
            if n in ctx.visited or junctions[ctx.head].get(direction):
                continue
            n_val = grid[n].value
            if n_val in cond or n_val in SLOPES and SLOPES[n_val] == direction:
                queue.append(SearchCtx(
                    head=n,
                    visited=ctx.visited | {ctx.head},
                    last_junction=ctx.head if is_junction_now else ctx.last_junction,
                    last_junction_dir=direction if is_junction_now else ctx.last_junction_dir,
                    last_junction_path=[ctx.head] if is_junction_now else ctx.last_junction_path + [ctx.head],
                ))

    log.debug(f"Junctions: {pprint.pformat({k: v for k, v in junctions.items() if v})}")
    return junctions


def _is_junction(grid: Grid, pos: Xy) -> bool:
    return sum([1 for n in grid.get_neighbors(pos) if grid[n].value in ">v<^"]) > 2


def _find_longest_path(grid: Grid, junctions: Dict[Xy, Dict[Direction, JunctionPath]]) -> int:
    start_pos = grid.find_first(".")
    end_pos = grid.find_last(".")
    queue = [SearchCtx(start_pos)]
    longest_paths = defaultdict(int)
    while queue:
        ctx = queue.pop()
        if ctx.head == end_pos:
            if len(ctx.visited) > longest_paths[ctx.head]:
                log.debug(f"Found path with {len(ctx.visited)} steps, {ctx.head}")
                longest_paths[ctx.head] = len(ctx.visited)
                continue
        for direction, junction_path in junctions[ctx.head].items():
            if junction_path.destination in ctx.visited:
                continue
            queue.append(SearchCtx(
                head=junction_path.destination,
                visited=(ctx.visited | set(junctions[ctx.head][direction].path)),
            ))
    return longest_paths[end_pos]


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 2070
    # Star 2: >= 6162
