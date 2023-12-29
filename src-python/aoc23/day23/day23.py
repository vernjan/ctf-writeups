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

    # prune junctions
    # reverse_junctions = _find_all_junctions(grid, start_pos=end_pos, end_pos=start_pos, cond=cond)
    # for pos, dirs in junctions.items():
    #     dirs2 = reverse_junctions[pos]
    #     if len(dirs.keys()) > len(dirs2.keys()):
    #     # if dirs.keys() != dirs2.keys():
    #         log.info(f"Junctions mismatch at {pos}: {dirs.keys()} vs {dirs2.keys()}")
    #         for k in (dirs2.keys()):
    #             if k in dirs:
    #                 log.info(f"Removing {k} from {pos}")
    #                 del junctions[pos][k]

    # reverse_junctions: Dict[Xy, Dict[Direction, JunctionPath]] = {}
    # for origin, connected_junctions in junctions.items():
    #     for direction, junction_path in connected_junctions.items():
    #         if junction_path.destination not in reverse_junctions:
    #             reverse_junctions[junction_path.destination] = {}
    #         reverse_junctions[junction_path.destination][direction] = (JunctionPath(
    #             path=list(reversed(junction_path.path)),
    #             destination=origin,
    #         ))
    # log.debug(f"Reverse junctions: {pprint.pformat(reverse_junctions)}")

    # junctions = {k: set(v.values()) for k, v in junctions.items()}
    # log.debug(f"Junctions FLAT: {pprint.pformat(junctions)}")

    # queue: List[Xy] = [end_pos]
    # while queue:
    #     pos = queue.pop(0)
    #     if pos not in reverse_junctions:
    #         break
    #     for direction, junction_path in reverse_junctions[pos].items():
    #         junction_pos = junction_path.destination
    #         if junction_pos in junctions and direction in junctions[junction_pos]:
    #             keep = junctions[junction_pos][direction]
    #             junctions[junction_pos] = {}
    #             junctions[junction_pos][direction] = keep
    #         queue.append(junction_pos)
    # log.debug(f"Junctions after: {pprint.pformat(junctions)}")
    # return _find_longest_path(start_pos=start_pos, end_pos=end_pos, junctions=junctions)
    junctions = {k: set(v.values()) for k, v in junctions.items()}

    return _find_longest_path(start_pos=start_pos, end_pos=end_pos, junctions=junctions)


def _find_all_junctions(grid: Grid, start_pos: Xy, end_pos: Xy, cond: str) -> Dict[Xy, Dict[Direction, JunctionPath]]:
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
                    # junctions[ctx.head][ctx.direction.turn_around()] = JunctionPath(list(reversed(ctx.last_junction_path)), ctx.last_junction)
                else:
                    continue

        for direction, n in grid.get_neighbors(ctx.head, include_directions=True):
            if n in ctx.visited:  # or junctions[ctx.head].get(direction):
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
    return junctions


def _is_junction(grid: Grid, pos: Xy) -> bool:
    return sum([1 for n in grid.get_neighbors(pos) if grid[n].value in ".>v<^"]) > 2


def _find_longest_path(start_pos: Xy, end_pos: Xy, junctions: Dict[Xy, Set[JunctionPath]]) -> int:
    queue = [SearchCtx(start_pos)]
    longest_paths = defaultdict(int)
    # cache: Dict[Xy, Dict[FrozenSet, int]] = defaultdict(dict)
    while queue:
        ctx = queue.pop()
        # if cache[ctx.head].get(frozenset(ctx.visited), -1) >= len(ctx.visited):
        #     continue
        # cache[ctx.head][frozenset(ctx.visited)] = len(ctx.visited)
        if ctx.head == end_pos:
            if len(ctx.visited) > longest_paths[end_pos]:
                log.debug(f"Found path with {len(ctx.visited)} steps, {ctx.head}, queue: {len(queue)}")
                longest_paths[end_pos] = len(ctx.visited)
            continue
        # for direction, junction_path in junctions[ctx.head].items():
        for junction_path in junctions[ctx.head]:
            if junction_path.destination in ctx.visited:
                continue
            queue.append(SearchCtx(
                head=junction_path.destination,
                visited=(ctx.visited | set(junction_path.path)),
            ))
    return longest_paths[end_pos]


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 2070
    # Star 2: 6498
