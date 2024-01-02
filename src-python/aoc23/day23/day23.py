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
    visited: Set[Xy] = field(default_factory=set)
    last_junction: Xy = None
    last_junction_dir: Direction = None
    last_junction_path: List[Xy] = field(default_factory=list)


@dataclass(frozen=True)
class Junction:
    destination: Xy
    path_len: int

    def __repr__(self):
        return f"{self.destination} ({self.path_len} steps)"

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
    >>> star2(read_test_input(__file__, "input-test-STAR2.txt"))
    154
    """
    return _solve(lines, ".")


def _solve(lines, cond: str):
    grid = Grid(lines)
    start_pos = grid.find_first(".")
    end_pos = grid.find_last(".")
    junctions = _find_all_junctions(grid, start_pos=start_pos, end_pos=end_pos, cond=cond)
    return _find_longest_path(start_pos=start_pos, end_pos=end_pos, junctions=junctions)


def _find_all_junctions(grid: Grid, start_pos: Xy, end_pos: Xy, cond: str) -> Dict[Xy, Set[Junction]]:
    junctions: Dict[Xy, Dict[Direction, Junction]] = defaultdict(dict)
    queue = [SearchCtx(start_pos)]
    while queue:
        ctx = queue.pop(0)
        is_junction_now = False
        if ctx.head in (start_pos, end_pos) or _is_junction(grid, ctx.head):
            is_junction_now = True
            if ctx.last_junction:
                if ctx.last_junction_dir not in junctions[ctx.last_junction]:
                    junctions[ctx.last_junction][ctx.last_junction_dir] = Junction(ctx.head,
                                                                                   len(ctx.last_junction_path))
                else:
                    continue

        for direction, n in grid.get_neighbors(ctx.head, include_directions=True):
            if n in ctx.visited:
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
    return {k: set(v.values()) for k, v in junctions.items()}


def _is_junction(grid: Grid, pos: Xy) -> bool:
    return sum([1 for n in grid.get_neighbors(pos) if grid[n].value in ".>v<^"]) > 2


def _find_longest_path(start_pos: Xy, end_pos: Xy, junctions: Dict[Xy, Set[Junction]]) -> int:
    queue = [(start_pos, set(), 0)]
    longest_path = 0
    while queue:
        head, visited, total_steps = queue.pop()
        if head == end_pos:
            if total_steps > longest_path:
                log.debug(f"Found path with {total_steps} steps, {head}, queue: {len(queue)}")
                longest_path = total_steps
            continue
        for junction in junctions[head]:
            if junction.destination in visited:
                continue
            queue.append((
                junction.destination,
                (visited | {head}),
                total_steps + junction.path_len,
            ))
    return longest_path


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__, "input-STAR2.txt")))

    # Star 1: 2070
    # Star 2: 6498  # Runs for 20 secs
