import heapq
import logging
from collections import defaultdict
from dataclasses import dataclass

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xy
from util.ds.grid import Grid
from util.functions import find_rsequence
from util.log import log


@dataclass(frozen=True)
class SearchCtx:
    pos: Xy
    steps: int

    def __lt__(self, other):
        return self.steps < other.steps


def star1(lines: list[str], max_dist: int):
    """
    >>> star1(read_test_input(__file__, "input-test.txt"), max_dist=6)
    16
    """
    grid = Grid(lines)
    _, result = list(_solve(grid, max_dist, yield_every_dist=False))[-1]
    return result


# >>> star2(read_test_input(__file__), max_dist=6)
# 16
# >>> star2(read_test_input(__file__), max_dist=10)
# 50
# >>> star2(read_test_input(__file__), max_dist=50)
# 1594
# >>> star2(read_test_input(__file__), max_dist=100)
# 6536
# >>> star2(read_test_input(__file__), max_dist=500)
# 167004
# >>> star2(read_test_input(__file__), max_dist=1000)
# 668697
# >>> star2(read_test_input(__file__), max_dist=5000)
# 16733044

def star2(lines: list[str], max_dist: int, enlarge_factor: int = 51):
    """
    >>> star2(read_test_input(__file__), max_dist=100)
    6536
    """

    enlarged = []
    for line in lines:
        enlarged.append(line * enlarge_factor)
    enlarged = enlarged * enlarge_factor

    grid = Grid(enlarged)
    orig_grid_size = len(lines)

    mid_y = grid.height // 2
    log.debug(f"mid_y={mid_y}")

    # y: [results for each dist]
    row_results_map = defaultdict(list)
    grid_results = []
    row_diffs_map = defaultdict(str)

    for dist, result in _solve(grid, 1000, yield_every_dist=True):
        log.debug(f"dist={dist}, result={result}")
        grid_results.append(result)
        # for y in range(mid_y - 4 * orig_grid_size, mid_y + 4 * orig_grid_size + 1):
    #     for y in range(mid_y, mid_y + 4 * orig_grid_size + 2):
    #         row_visited = sum(1 for cell in grid.rows[y][mid_y - dist:mid_y + dist + 1] if cell.value == "x")
    #         if len(row_results_map[y]):
    #             row_diffs_map[y] += str(row_visited - row_results_map[y][-1])
    #         row_results_map[y].append(row_visited)
    #
    # log.debug(f"row_results={row_results_map}")
    # log.debug(f"row_diffs={row_diffs_map}")

    for y, grid_result in row_diffs_map.items():
        first_index, r_seq_size = find_rsequence(grid_result, pattern_size=7, confidence=2)
        if first_index >= 0:
            log.debug(f"y={y}, first_index={first_index}, r_seq_size={r_seq_size}")
        else:
            assert False, f"Repeating sequence not found, y={y}, row_diffs={grid_result}"

    # total_match_count = 0
    # no_match_count = 0
    # for y1, row_diffs1 in row_diffs_map.items():
    #     test_seq_len = 20
    #     seq1 = list(itertools.dropwhile(lambda x: x == "0", row_diffs1))[:test_seq_len]
    #     assert len(seq1) == test_seq_len
    #     log.debug(f"Checking pattern for y={y1}, seq={seq1}")
    #     for y2, row_diffs2 in row_diffs_map.items():
    #         seq2 = list(itertools.dropwhile(lambda x: x == "0", row_diffs2))[:test_seq_len]
    #         if seq1 == seq2 and y1 != y2:
    #             match_dist = abs(y2 - y1)
    #             if match_dist == 2 * orig_grid_size:
    #                 total_match_count += 1
    #                 log.debug(f"MATCH FOUND={match_dist}")
    #                 break
    #     else:
    #         no_match_count += 1
    #         log.debug(f"NO MATCH FOUND")
    #
    # assert no_match_count == 1

    # diffs = []
    # dif_diffs = []
    # for row_diffs in row_diffs_map.values():
    #     diffs.append(sum(map(int, row_diffs)))
    #     if len(diffs) > 1:
    #         dif_diffs.append(abs(diffs[-2] - diffs[-1]))
    #
    # log.debug(f"diffs={diffs}")
    # log.debug(f"dif_diffs={dif_diffs}")
    # first, size = find_rsequence(dif_diffs, pattern_size=7, confidence=2)
    # log.debug(f"first={first}, size={size}")

    diffs = []
    for grid_result in grid_results:
        diffs.append(grid_result)
        if len(diffs) > 1:
            diffs.append(abs(diffs[-2] - diffs[-1]))

    log.debug(f"grid_result={grid_results}")
    log.debug(f"diffs={diffs}")
    first, size = find_rsequence(diffs, pattern_size=25, confidence=2)
    log.debug(f"first={first}, size={size}")


def _solve(grid, max_dist: int, yield_every_dist=False):
    start_pos = Xy(grid.height // 2, grid.width // 2)
    queue = []
    heapq.heappush(queue, SearchCtx(start_pos, 0))
    current_dist = 0
    visited_count = 0
    max_dist_remainder = max_dist % 2
    while queue:
        ctx = heapq.heappop(queue)
        pos, steps = ctx.pos, ctx.steps
        cell = grid.get_cell(pos)
        if cell.visited:
            continue
        cell.visited = True
        if steps % 2 == max_dist_remainder:
            cell.value = "x"
            visited_count += 1
        if steps > current_dist:
            yield current_dist, visited_count
            current_dist = steps
        if steps > max_dist:
            break
        for n_pos in grid.get_neighbors(pos):
            if grid.get_cell(n_pos).value in ".S":
                heapq.heappush(queue, SearchCtx(n_pos, steps + 1))


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    # timed_run("Star 1", lambda: star1(read_input(__file__), max_dist=64))
    # timed_run("Star 2", lambda: star2(read_input(__file__, "input-test.txt"), max_dist=64, enlarge_factor=201))
    timed_run("Star 2", lambda: star2(read_input(__file__, "input.txt"), max_dist=26501365, enlarge_factor=17))

    # Star 1: 3598
    # Star 2:
