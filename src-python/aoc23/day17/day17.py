import heapq
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xy, Direction, EAST, SOUTH
from util.ds.grid import Grid
from util.log import log


@dataclass(frozen=True)
class SearchCtx:
    pos: Xy = None
    total_heat_loss: int = 0
    straight_blocks: int = 0
    dir: Direction = None
    path: List["SearchCtx"] = field(default_factory=list)  # just for visualization

    def __lt__(self, other):
        return self.total_heat_loss < other.total_heat_loss


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    102
    """
    return _solve(lines, min_straight_blocks=1, max_straight_blocks=3)


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    94
    >>> star2(read_test_input(__file__, "input-test2.txt"))
    71
    """
    return _solve(lines, min_straight_blocks=4, max_straight_blocks=10)


def _solve(lines, min_straight_blocks: int, max_straight_blocks: int) -> int:
    def is_potentially_good():
        for (direction, straight_blocks), total_heat_loss in cache[next_ctx.pos].items():
            opposite_direction = direction.turn_around()  # coming from the opposite directions is equivalent
            if next_ctx.total_heat_loss >= total_heat_loss:
                if next_ctx.dir in (direction, opposite_direction):
                    if next_ctx.straight_blocks >= straight_blocks:
                        return False
        return True

    grid = Grid(lines)
    total_steps = 0
    end_pos = Xy(grid.width - 1, grid.height - 1)
    start_ctx1 = SearchCtx(Xy(1, 0), int(grid.get_value(Xy(1, 0))), straight_blocks=1, dir=EAST)
    start_ctx2 = SearchCtx(Xy(0, 1), int(grid.get_value(Xy(0, 1))), straight_blocks=1, dir=SOUTH)
    cache: Dict[Xy, Dict[Tuple[Direction, int], int]] = defaultdict(dict)

    queue = []
    heapq.heappush(queue, start_ctx1)
    heapq.heappush(queue, start_ctx2)
    while queue:
        ctx = heapq.heappop(queue)
        total_steps += 1

        # end reached - visualization
        if ctx.pos == end_pos and ctx.total_heat_loss <= min(cache[end_pos].values()):
            if log.level == logging.DEBUG:
                log.debug(f"Found solution: {ctx.total_heat_loss} (total steps: {total_steps})")
                temp_grid = Grid(lines)
                for cctx in ctx.path:
                    temp_grid.set_value(cctx.pos, cctx.dir)
                log.debug(temp_grid)
            continue

        next_possible_dirs = [ctx.dir.turn_right(), ctx.dir.turn_left()]
        if ctx.straight_blocks < max_straight_blocks:
            next_possible_dirs.append(ctx.dir)
        for next_dir in next_possible_dirs:
            is_turn = ctx.dir != next_dir
            next_ctx = ctx
            for i in range(min_straight_blocks if is_turn else 1):
                next_pos = next_ctx.pos.neighbor(next_dir)
                if not grid.has(next_pos):
                    break  # this skips the for-else block
                next_ctx = SearchCtx(
                    pos=next_pos,
                    total_heat_loss=next_ctx.total_heat_loss + int(grid.get_value(next_pos)),
                    straight_blocks=1 if (is_turn and i == 0) else (next_ctx.straight_blocks + 1),
                    dir=next_dir,
                    path=next_ctx.path + [next_ctx] if log.level == logging.DEBUG else None,
                )
            else:
                if is_potentially_good():
                    cache[next_ctx.pos][(next_ctx.dir, next_ctx.straight_blocks)] = next_ctx.total_heat_loss
                    heapq.heappush(queue, next_ctx)

    log.debug(f"Total steps: {total_steps}")
    return min(cache[end_pos].values())


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 797
    # Star 2: 914
