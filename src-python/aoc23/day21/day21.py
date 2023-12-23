import heapq
import logging
import math
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
    >>> star1(read_input(__file__), max_dist=32)
    902
    >>> star1(read_input(__file__), max_dist=64)
    3598
    >>> star1(read_input(__file__), max_dist=1)
    4
    >>> star1(read_input(__file__), max_dist=2)
    7
    >>> star1(read_test_input(__file__), max_dist=1)
    2
    >>> star1(read_test_input(__file__), max_dist=2)
    4
    >>> star1(read_input(__file__), max_dist=499)
    214288
    >>> star1(read_input(__file__), max_dist=500)
    215119
    """

    enlarged = []
    for line in lines:
        enlarged.append(line * 9)
    enlarged = enlarged * 9

    grid = Grid(enlarged)
    _, result = list(_solve(grid, max_dist))[-1]
    # log.debug(result)
    # log.debug(grid)
    return result


def star2(lines: list[str], max_dist: int, enlarge_factor: int = 21):
    """
    >>> star1(read_test_input(__file__), max_dist=1)
    2
    >>> star1(read_test_input(__file__), max_dist=2)
    4
    >>> star2(read_test_input(__file__), max_dist=3)
    6
    >>> star2(read_test_input(__file__), max_dist=5)
    13
    >>> star2(read_test_input(__file__), max_dist=50)
    1594
    >>> star2(read_test_input(__file__), max_dist=51)
    1653
    >>> star2(read_test_input(__file__), max_dist=100)
    6536
    >>> star2(read_test_input(__file__), max_dist=500)
    167004
    >>> star2(read_test_input(__file__), max_dist=5000)
    16733044
    >>> star2(read_input(__file__), max_dist=1, enlarge_factor=1)
    4
    >>> star2(read_input(__file__), max_dist=2, enlarge_factor=17)
    7
    >>> star2(read_input(__file__), max_dist=32, enlarge_factor=17)
    902
    >>> star2(read_input(__file__), max_dist=64, enlarge_factor=17)
    3598
    >>> star2(read_input(__file__), max_dist=128, enlarge_factor=17)
    14219
    >>> star2(read_input(__file__), max_dist=499, enlarge_factor=17)
    214288
    >>> star2(read_input(__file__), max_dist=500, enlarge_factor=17)
    215119
    """

    # rseq_maps = {
    #     "N": {},
    #     "S": {},
    # }
    # rseq_lines = read_test_input(__file__, "rseq-EVEN.txt")
    # for i, rseq_line in enumerate(rseq_lines):
    #     direction = "N" if i < len(rseq_lines) // 2 else "S"
    #     y, first_index, rseq = rseq_line.split(";")
    #     rseq_maps[direction][int(y)] = RSequence(list(map(int, rseq[1:-1].split(","))), first_index=int(first_index))
    #
    # mid_y = int(rseq_lines[len(rseq_lines) // 2].split(";")[0])
    # rseq_maps["N"][mid_y] = rseq_maps["S"][mid_y]

    orig_grid_size = len(lines)
    no_match_count = 0
    total = 0

    # # TODO Move into Grid
    enlarged = []
    for line in lines:
        enlarged.append(line * enlarge_factor)
    enlarged = enlarged * enlarge_factor

    grid = Grid(enlarged)
    mid_y = grid.height // 2
    max_dist_samples = (enlarge_factor // 2) * orig_grid_size
    if max_dist % 2 != max_dist_samples % 2:
        max_dist_samples += 1
    log.debug(f"mid_y={mid_y}")
    log.debug(f"max_dist_samples={max_dist_samples}")

    # y: [results for each dist]
    grid_results = []
    last_row_results_maps = {
        "N": defaultdict(list),
        "S": defaultdict(list),
    }
    row_diff_maps = {
        "N": defaultdict(str),
        "S": defaultdict(str),
    }
    rseq_maps = {
        "N": {},
        "S": {},
    }

    def count_visited(y) -> int:
        return sum(1 for cell in grid.rows[y][mid_y - dist:mid_y + dist + 1] if cell.value == "x")

    for dist, result in _solve(grid, max_dist_samples):
        log.debug(f"dist={dist}, result={result}")
        grid_results.append(result)

        for i in range(dist + 1):
            for direction, row_diff_map in row_diff_maps.items():
                y = mid_y + i if direction == "S" else mid_y - i
                row_visited = count_visited(y)
                last_row_visited = last_row_results_maps[direction][y][-1] if len(
                    last_row_results_maps[direction][y]) else 0
                row_diff_map[y] += str(row_visited - last_row_visited)
                last_row_results_maps[direction][y].append(row_visited)

    log.debug(f"grid_results={grid_results}")

    min_pattern_size = 3 * orig_grid_size

    for direction, row_diff_map in row_diff_maps.items():
        row_diff_map = {k: v for k, v in row_diff_map.items() if len(v) >= min_pattern_size}
        samples_count = len(row_diff_map)
        log.debug(f"row_diff_map-{direction}={row_diff_map.items()}")
        log.debug(f"samples collected: {samples_count}")
        assert samples_count > 3 * orig_grid_size, f"Not enough samples collected: {samples_count}"

        # make sure we have repeating sequences for each row
        for y, row_diffs in row_diff_map.items():
            rseq = find_rsequence(list(map(int, row_diffs)), pattern_size=orig_grid_size, confidence=2)
            assert rseq.first_index >= 0, f"Repeating sequence not found, y={y}, row_diffs={row_diffs}"
            assert rseq.rsize <= orig_grid_size, f"Repeating sequence too large, y={y}, r_seq_size={rseq.rsize}"
            assert rseq.first_index <= 2 * orig_grid_size, f"First index too high, y={y}, first_index={rseq.first_index}"
            log.debug(f"y={y}, first_index={rseq.first_index}, r_seq_size={rseq.rsize}")
            rseq_maps[direction][y] = rseq

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

        log.info(f"no_match_count={no_match_count}, mid_y={mid_y}, samples_count={samples_count}")
        assert no_match_count <= 2 * orig_grid_size, f"Too many mismatches: {no_match_count}"

        log.info(f"rseqs-{direction}")
        f = open("rseq.txt", "w")
        for y, rseq in rseq_maps[direction].items():
            f.write(f"{y};{rseq.first_index};{rseq.seq}\n")
        f.close()

    assert rseq_maps["S"][mid_y] == rseq_maps["N"][mid_y]

    for direction in ["N", "S"]:
        for i in range(max_dist + 1):
            if i % 100_000 == 0:
                log.info(f"PROGRESS i={i}, total={total}")

            if i <= 2 and max_dist % 2 == 0:
                total_items = max_dist // 2
            else:
                total_items = (max_dist - i) // 2 + 1

            offset = i
            if offset > no_match_count + 2 * orig_grid_size:
                offset = no_match_count + (i - no_match_count) % (2 * orig_grid_size)

            y = mid_y + offset if direction == "S" else mid_y - offset

            rseq = rseq_maps[direction][y]
            subtotal = rseq.rsum(total_items)
            log.debug(f"y={y}, total_items={total_items}, subtotal={subtotal}, rseq={rseq.seq}[{rseq.first_index}:]")
            total += subtotal

    total -= rseq_maps["S"][mid_y].rsum(total_items=math.ceil(max_dist / 2))
    return total


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
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__), max_dist=64))
    timed_run("Star 2", lambda: star2(read_input(__file__, "input.txt"), max_dist=26501365, enlarge_factor=21))

    # Star 1: 3598
    # Star 2: 601441063166538
