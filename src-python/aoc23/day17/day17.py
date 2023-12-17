import dataclasses
import logging
from collections import defaultdict
from typing import Dict

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xy, Direction, EAST, SOUTH
from util.ds.grid import Grid
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    102
    """

    @dataclasses.dataclass(frozen=True)
    class SearchCtx:
        pos: Xy = None
        total_heat_loss: int = 0
        straight_moves: int = 0
        dir: Direction = None

    grid = Grid(lines)
    start_ctx1 = SearchCtx(pos=Xy(1, 0), total_heat_loss=int(grid.get_value(Xy(1, 0))), straight_moves=1, dir=EAST)
    start_ctx2 = SearchCtx(pos=Xy(0, 1), total_heat_loss=int(grid.get_value(Xy(0, 1))), straight_moves=1, dir=SOUTH)
    cache: Dict[Xy, Dict[int, int]] = defaultdict(dict)
    queue = [start_ctx1, start_ctx2]
    while queue:
        ctx = queue.pop(0)

        cached_total_heat_loss = cache[ctx.pos].get(ctx.straight_moves)
        if cached_total_heat_loss and cached_total_heat_loss < ctx.total_heat_loss:
            continue
        cache[ctx.pos][ctx.straight_moves] = ctx.total_heat_loss

        for next_dir in [ctx.dir.turn_left(), ctx.dir.turn_right(), ctx.dir]:
            next_pos = ctx.pos.neighbor(next_dir)
            is_turn = ctx.dir != next_dir
            if grid.has(next_pos) and (is_turn or ctx.straight_moves < 3):
                new_search_ctx = SearchCtx(
                    pos=next_pos,
                    total_heat_loss=ctx.total_heat_loss + int(grid.get_value(ctx.pos)),
                    straight_moves=0 if is_turn else (ctx.straight_moves + 1),
                    dir=next_dir,
                )
                queue.append(new_search_ctx)

    end_pos = (Xy(grid.width - 1, grid.height - 1))
    log.debug(cache[end_pos])
    return min(cache[end_pos].values()) + int(grid.get_value(end_pos))


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

    # Star 1:
    # Star 2:
