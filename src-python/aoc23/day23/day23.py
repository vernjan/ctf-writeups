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


@dataclass(frozen=True)
class SearchCtx:
    head: Xy
    direction: Direction = None
    visited: Set[Xy] = field(default_factory=set)
    last_junction: Xy = None
    last_junction_dir: Direction = None
    last_junction_path: List[Xy] = field(default_factory=list)


@dataclass(frozen=True)
class JunctionPath:
    path: List[Xy]
    destination: Xy

    def __repr__(self):
        return f"{self.destination} ({len(self.path)} steps)"

    def __hash__(self):
        return hash(self.destination)


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
    start_pos = grid.find_first(".")
    end_pos = grid.find_last(".")
    junctions = _find_all_junctions(grid, start_pos=start_pos, end_pos=end_pos, cond=cond)
    return _find_longest_path(start_pos=start_pos, end_pos=end_pos, junctions=junctions)


def _find_all_junctions(grid: Grid, start_pos: Xy, end_pos: Xy, cond: str) -> Dict[Xy, Set[JunctionPath]]:
    """
    >>> len(dict(_find_all_junctions(Grid(read_test_input(__file__)),".<>v^")))
    8
    """
    junctions: Dict[Xy, Dict[Direction, JunctionPath]] = defaultdict(dict)
    queue = [SearchCtx(start_pos)]
    while queue:
        ctx = queue.pop(0)
        is_junction_now = False
        if ctx.head in (start_pos, end_pos) or _is_junction(grid, ctx.head):
            is_junction_now = True
            if ctx.last_junction:
                if ctx.last_junction_dir not in junctions[ctx.last_junction]:
                    junctions[ctx.last_junction][ctx.last_junction_dir] = JunctionPath(ctx.last_junction_path, ctx.head)
                else:
                    continue

        for direction, n in grid.get_neighbors(ctx.head, include_directions=True):
            if n in ctx.visited:
                continue
            n_val = grid[n].value
            if n_val in cond or n_val in SLOPES and SLOPES[n_val] == direction:
                queue.append(SearchCtx(
                    head=n,
                    direction=direction,
                    visited=ctx.visited | {ctx.head},
                    last_junction=ctx.head if is_junction_now else ctx.last_junction,
                    last_junction_dir=direction if is_junction_now else ctx.last_junction_dir,
                    last_junction_path=[ctx.head] if is_junction_now else ctx.last_junction_path + [ctx.head],
                ))

    log.debug(f"Junctions: {pprint.pformat({k: v for k, v in junctions.items() if v})}")
    return {k: set(v.values()) for k, v in junctions.items()}


def _is_junction(grid: Grid, pos: Xy) -> bool:
    return sum([1 for n in grid.get_neighbors(pos) if grid[n].value in ".>v<^"]) > 2


def _find_longest_path(start_pos: Xy, end_pos: Xy, junctions: Dict[Xy, Set[JunctionPath]]) -> int:
    queue = [SearchCtx(start_pos)]
    longest_paths = defaultdict(int)
    while queue:
        ctx = queue.pop()
        if ctx.head == end_pos:
            if len(ctx.visited) > longest_paths[end_pos]:
                log.debug(f"Found path with {len(ctx.visited)} steps, {ctx.head}, queue: {len(queue)}")
                longest_paths[end_pos] = len(ctx.visited)
            continue
        for junction_path in junctions[ctx.head]:
            if junction_path.destination in ctx.visited:
                continue
            queue.append(SearchCtx(
                head=junction_path.destination,
                visited=(ctx.visited | set(junction_path.path)),
            ))
    return longest_paths[end_pos]


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 2070
    # Star 2: 6498  # Runs for 15 mins ...
