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

    @dataclasses.dataclass
    class SearchCtx:
        pos: Xy = None
        total_heat_loss: int = 0
        straight_moves: int = 0
        dir: Direction = None
        prev_ctx: "SearchCtx" = None

    total_steps = 0
    grid = Grid(lines)
    end_pos = Xy(grid.width - 1, grid.height - 1)
    start_ctx1 = SearchCtx(pos=Xy(1, 0), total_heat_loss=int(grid.get_value(Xy(1, 0))), straight_moves=1, dir=EAST)
    start_ctx2 = SearchCtx(pos=Xy(0, 1), total_heat_loss=int(grid.get_value(Xy(0, 1))), straight_moves=1, dir=SOUTH)
    cache: Dict[Xy, Dict[int, int]] = defaultdict(dict)
    # current_best_solution = (grid.width + grid.height) * 9
    current_best_solution = 1391
    # current_best_solution = 500
    queue = [start_ctx1, start_ctx2]
    while queue:
        ctx = queue.pop(0)

        worst_possible = 9 * (ctx.pos.x + ctx.pos.y)
        if ctx.total_heat_loss > worst_possible:
            continue

        cache_hit = is_worse_solution(cache, ctx, current_best_solution)
        if cache_hit:
            continue

        # TODO Remove me, simple cache
        # total_heat_loss = cache[ctx.pos].get(ctx.straight_moves)
        # if total_heat_loss and total_heat_loss < ctx.total_heat_loss:
        #     continue

        total_steps += 1

        prev_ctx = ctx.prev_ctx
        b = False
        while prev_ctx:
            if is_worse_solution(cache, prev_ctx, current_best_solution):
                b = True
                break
            prev_ctx = prev_ctx.prev_ctx
        if b:
            continue

        cache[ctx.pos][ctx.straight_moves] = ctx.total_heat_loss
        # for qctx in queue:
        #     if is_worse_solution(cache, qctx, current_best_solution):
        #         while qctx.prev_ctx:
        #             # log.debug(f"Pruning queue {qctx}")
        #             if qctx in queue:
        #                 queue.remove(qctx)
        #                 qctx = qctx.prev_ctx
        #             else:
        #                 break

                # end reached
        if ctx.pos == end_pos:
            if not current_best_solution or ctx.total_heat_loss < current_best_solution:
                current_best_solution = ctx.total_heat_loss
                # gtemp = Grid(lines)
                # for p in ctx.path:
                #     gtemp.set_value(p, "X")
                log.debug(f"Found path: {ctx.total_heat_loss} (total steps: {total_steps}, queue size: {len(queue)})")
                # log.debug(gtemp)
            continue

        if total_steps % 100_000 == 0:
            log.debug(f"Cache size: {len(cache)}, total steps: {total_steps}, queue size: {len(queue)}")

        for next_dir in [ctx.dir, ctx.dir.turn_right(), ctx.dir.turn_left()]:
            next_pos = ctx.pos.neighbor(next_dir)
            is_turn = ctx.dir != next_dir
            if grid.has(next_pos) and (is_turn or ctx.straight_moves < 2):
                new_search_ctx = SearchCtx(
                    pos=next_pos,
                    total_heat_loss=ctx.total_heat_loss + int(grid.get_value(next_pos)),
                    straight_moves=0 if is_turn else (ctx.straight_moves + 1),
                    dir=next_dir,
                    prev_ctx=ctx
                    # path=ctx.path + [next_pos]
                )
                # ctx.next_ctx = new_search_ctx
                queue.append(new_search_ctx)

    log.debug(f"Total steps: {total_steps}")
    return min(cache[(end_pos)].values())


def is_worse_solution(cache, ctx, current_best_solution):
    cache_hit = False
    for straight_moves, total_heat_loss in cache[ctx.pos].items():
        if current_best_solution and ctx.total_heat_loss > current_best_solution:
            cache_hit = True
            break
        if ctx.straight_moves >= straight_moves and total_heat_loss < ctx.total_heat_loss:
            cache_hit = True
            break
    return cache_hit


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))

    """
    for line in lines:
        pass


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1:
    # Star 2:
