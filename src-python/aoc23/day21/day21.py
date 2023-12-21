import logging

from util.data_io import read_input, read_test_input, timed_run
from util.ds.grid import Grid
from util.log import log


def star1(lines: list[str], max_dist: int):
    """
    >>> star1(read_test_input(__file__, "input-test-large.txt"), max_dist=6)
    16
    >>> star1(read_test_input(__file__, "input-test-large.txt"), max_dist=10)
    50
    >>> star1(read_test_input(__file__, "input-test-large.txt"), max_dist=50)
    1594
    >>> star1(read_test_input(__file__, "input-test-large.txt"), max_dist=100)
    6536
    """

    # grid = Grid(lines)
    # return _solve(grid, max_dist)

    res = 0
    c = 0
    results = []
    while True:
        c += 2
        grid = Grid(lines)
        new_res = _solve(grid, c)
        log.debug(f"c={c}, res={new_res}, diff: {new_res - res}")
        results.append(new_res)
        if res and new_res == res or c == 152:
            break
        res = new_res
    log.debug(results)


def _solve(grid, max_dist: int):
    start_pos = grid.find_first("S")
    grid.set_value(start_pos, ".")
    queue = [(0, start_pos)]
    c = 0
    while queue:
        steps, pos = queue.pop(0)
        if pos.x == 0 or pos.x == grid.height - 1 or pos.y == 0 or pos.y == grid.width - 1:
            log.info("Edge reached")
        cell = grid.get_cell(pos)
        if cell.visited:
            continue
        cell.visited = True
        if steps % 2 == 0:
            cell.value = "x"
        if steps >= max_dist:
            continue
        c += 1
        for n_pos in grid.get_neighbors(pos):
            if grid.get_cell(n_pos).value == ".":
                queue.append((steps + 1, n_pos))
    # log.info(f"c={c}")
    # log.debug(grid)
    return sum(1 for cell in grid.get_all_cells() if cell.value == "x")


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))

    """
    for line in lines:
        pass


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    # timed_run("Star 1", lambda: star1(read_input(__file__), max_dist=64))
    timed_run("Star 1", lambda: star1(read_input(__file__, "input-test-large.txt"), max_dist=64))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 3598
    # Star 2:
