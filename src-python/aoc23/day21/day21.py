import heapq
import logging
from collections import defaultdict
from dataclasses import dataclass

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xy
from util.ds.grid import Grid
from util.functions import find_rsequence, sum_rsequence
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
    _, result = list(_solve(grid, max_dist))[-1]
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

    log.debug(f"orig_grid_size={len(lines)}")
    grid = Grid(enlarged)
    orig_grid_size = len(lines)

    mid_y = grid.height // 2
    max_dist_samples = (enlarge_factor // 2) * orig_grid_size
    if max_dist % 2 != max_dist_samples % 2:
        max_dist_samples += 1
    log.debug(f"mid_y={mid_y}")
    log.debug(f"max_dist_samples={max_dist_samples}")

    # y: [results for each dist]
    grid_results = []
    row_results_map = defaultdict(list)
    row_diff_maps = {
        "N": defaultdict(str),
        "S": defaultdict(str),
    }

    # TODO I'm counting the mid row twice !!
    def count_visited(y) -> int:
        return sum(1 for cell in grid.rows[y][mid_y - dist:mid_y + dist + 1] if cell.value == "x")

    for dist, result in _solve(grid, max_dist_samples):
        log.debug(f"dist={dist}, result={result}")
        grid_results.append(result)

        for i in range(0, dist, 1):
            for direction, row_diff_map in row_diff_maps.items():
                y = mid_y + i if direction == "S" else mid_y - i
                row_visited = count_visited(y)
                if len(row_results_map[y]):
                    row_diff_map[y] += str(row_visited - row_results_map[y][-1])
                row_results_map[y].append(row_visited)

    log.debug(f"grid_results={grid_results}")

    min_pattern_size = 3 * orig_grid_size

    for direction, row_diff_map in row_diff_maps.items():
        row_diff_map = {k: v for k, v in row_diff_map.items() if len(v) >= min_pattern_size}
        samples_count = len(row_diff_map)
        log.debug(f"row_diff_map-{direction}={row_diff_map.items()}")
        log.debug(f"samples collected: {samples_count}")
        assert samples_count > 4 * orig_grid_size, f"Not enough samples collected: {samples_count}"

        # make sure we have repeating sequences for each row
        for y, row_diffs in row_diff_map.items():
            first_index, r_seq_size = find_rsequence(row_diffs, pattern_size=orig_grid_size, confidence=2)
            assert first_index >= 0, f"Repeating sequence not found, y={y}, row_diffs={row_diffs}"
            assert r_seq_size <= orig_grid_size, f"Repeating sequence too large, y={y}, r_seq_size={r_seq_size}"
            assert first_index <= 2 * orig_grid_size, f"First index too high, y={y}, first_index={first_index}"
            log.debug(f"y={y}, first_index={first_index}, r_seq_size={r_seq_size}")

        no_match_count = 0
        row_diff_map_reverted = sorted(row_diff_map.items(), reverse=True)
        for y1, row_diffs1 in row_diff_map_reverted:
            row_diffs1 = row_diffs1[:min_pattern_size]
            log.debug(f"Searching for repeating rows for y={y1}, seq={row_diffs1}")
            for y2, row_diffs2 in row_diff_map_reverted:
                if row_diffs2.startswith(row_diffs1) and y1 != y2:
                    match_dist = abs(y2 - y1)
                    if match_dist == 2 * orig_grid_size:
                        log.debug(f"MATCH FOUND={match_dist}")
                        break
            else:
                no_match_count += 1
                log.debug(f"NO MATCH FOUND")

        log.debug(f"no_match_count={no_match_count}, mid_y={mid_y}, samples_count={samples_count}")
        assert no_match_count <= 2 * orig_grid_size, f"Too many mismatches: {no_match_count}"

    total = 0
    for direction, row_diff_map in row_diff_maps.items():
        for i in range(max_dist):
            total_items = max_dist - i
            y = mid_y + i if direction == "S" else mid_y - i
            total += sum_rsequence(list(map(int, row_diff_map[y])), total_items, pattern_size=orig_grid_size,
                                   confidence=2)

    total -= sum_rsequence(list(map(int, row_diff_maps["S"][mid_y])), max_dist, pattern_size=orig_grid_size,
                           confidence=2)
    return total

    # diffs = []
    # for grid_result in grid_results:
    #     diffs.append(grid_result)
    #     if len(diffs) > 1:
    #         diffs[-1] = abs(diffs[-2] - diffs[-1])
    # del diffs[:no_match_count]
    #
    # log.debug(f"grid_result={grid_results}")
    # log.debug(f"diffs={diffs}")
    # # first, size = find_rsequence(diffs, pattern_size=25, confidence=2)
    # # log.debug(f"first={first}, size={size}")


def _solve(grid, max_dist: int):
    start_pos = Xy(grid.height // 2, grid.width // 2)
    queue = []
    heapq.heappush(queue, SearchCtx(start_pos, 0))
    current_dist = 0
    visited_count = 0
    max_dist_remainder = max_dist % 2
    while queue:
        ctx = heapq.heappop(queue)
        pos, steps = ctx.pos, ctx.steps
        if steps > max_dist:
            yield current_dist, visited_count
            break
        cell = grid.get_cell(pos)
        if cell.visited:
            continue
        cell.visited = True
        if steps % 2 == max_dist_remainder:
            if steps > current_dist > 0:
                yield current_dist, visited_count
            current_dist = steps
            cell.value = "x"
            visited_count += 1
        for n_pos in grid.get_neighbors(pos):
            if grid.get_cell(n_pos).value in ".S":
                heapq.heappush(queue, SearchCtx(n_pos, steps + 1))


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    # timed_run("Star 1", lambda: star1(read_input(__file__), max_dist=64))
    timed_run("Star 2", lambda: star2(read_input(__file__, "input-test.txt"), max_dist=50, enlarge_factor=51))
    # timed_run("Star 2", lambda: star2(read_input(__file__, "input.txt"), max_dist=26501365, enlarge_factor=21))

    # Star 1: 3598
    # Star 2:
