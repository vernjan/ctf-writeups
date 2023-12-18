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
    path: List["SearchCtx"] = field(default_factory=list)

    def __lt__(self, other):
        return self.total_heat_loss < other.total_heat_loss


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    102
    """
    return _solve("s1", lines, min_straight=0, max_straight=3)


# FIXME not working for input-test2, lucky for me it works for the real input
def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    94
    >>> star2(read_test_input(__file__, "input-test2.txt"))
    71
    """
    return _solve("s2", lines, min_straight=4, max_straight=10)


def _solve(star, lines, min_straight: int, max_straight: int) -> int:
    def is_potentially_good():
        for (direction, straight_moves), total_heat_loss in cache[new_ctx.pos].items():
            if new_ctx.total_heat_loss >= total_heat_loss:
                if new_ctx.dir == direction:
                    if star == "s1" and new_ctx.straight_blocks >= straight_moves:
                        return False
                    if star == "s2" and new_ctx.straight_blocks == straight_moves:
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
        if total_steps % 100000 == 0:
            log.debug(f"Cache size: {len(cache)}, total steps: {total_steps}, queue size: {len(queue)}")

        # end reached
        if ctx.pos == end_pos and ctx.total_heat_loss <= min(cache[end_pos].values()):
            if log.level == logging.DEBUG:
                log.debug(f"Found solution: {ctx.total_heat_loss} (total steps: {total_steps})")
                temp_grid = Grid(lines)
                for cctx in ctx.path:
                    temp_grid.set_value(cctx.pos, cctx.dir)
                log.debug(temp_grid)
            continue

        # TBD
        next_dirs = []
        if min_straight <= ctx.straight_blocks < max_straight:
            next_dirs.append(ctx.dir)
        if ctx.straight_blocks >= min_straight:
            next_dirs.extend([ctx.dir.turn_right(), ctx.dir.turn_left()])

            # if ctx.straight_blocks == 1 and min_straight > 1:  # after turn, go straight

        for next_dir in next_dirs:
            next_pos = ctx.pos.neighbor(next_dir)
            is_turn = ctx.dir != next_dir

            if is_turn and min_straight > 1:
                new_ctx = ctx
                ok = True
                for _ in range(min_straight - 1):
                    next_pos = new_ctx.pos.neighbor(next_dir)
                    if grid.has(next_pos):
                        new_ctx = SearchCtx(
                            pos=next_pos,
                            total_heat_loss=new_ctx.total_heat_loss + int(grid.get_value(next_pos)),
                            straight_blocks=new_ctx.straight_blocks + 1,
                            dir=ctx.dir,
                            path=new_ctx.path + [new_ctx] if log.level == logging.DEBUG else None,
                        )
                    else:
                        ok = False
                        break
                if ok:
                    if is_potentially_good():
                        cache[new_ctx.pos][(new_ctx.dir, new_ctx.straight_blocks)] = new_ctx.total_heat_loss
                        heapq.heappush(queue, new_ctx)


            elif grid.has(next_pos):
                new_ctx = SearchCtx(
                    pos=next_pos,
                    total_heat_loss=ctx.total_heat_loss + int(grid.get_value(next_pos)),
                    straight_blocks=1 if is_turn else (ctx.straight_blocks + 1),
                    dir=next_dir,
                    path=ctx.path + [ctx] if log.level == logging.DEBUG else None,
                )
                if is_potentially_good():
                    cache[new_ctx.pos][(new_ctx.dir, new_ctx.straight_blocks)] = new_ctx.total_heat_loss
                    heapq.heappush(queue, new_ctx)

    log.debug(f"Total steps: {total_steps}")
    return min(cache[end_pos].values())


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 797
    # Star 2: 914
