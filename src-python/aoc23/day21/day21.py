import logging

from util.data_io import read_input, read_test_input, timed_run
from util.ds.grid import Grid
from util.log import log


def star1(lines: list[str], max_dist: int):
    """
    >>> star1(read_test_input(__file__), max_dist=6)
    16
    """
    grid = Grid(lines)
    return _solve(grid, max_dist)


def _solve(grid, max_dist: int):
    start_pos = grid.find_first("S")
    grid.set_value(start_pos, ".")
    queue = [(0, start_pos)]
    while queue:
        steps, pos = queue.pop(0)
        cell = grid.get_cell(pos)
        if steps % 2 == 0:
            if cell.meta == "even":
                continue
            cell.meta = "even"
        if steps >= max_dist:
            continue
        for n_pos in grid.get_neighbors(pos):
            n_cell = grid.get_cell(n_pos)
            if n_cell.value == "." and n_cell.meta != "even":
                queue.append((steps + 1, n_pos))
    return sum(1 for cell in grid.get_all_cells() if cell.meta == "even")


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))

    """
    for line in lines:
        pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__), max_dist=64))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 3598
    # Star 2:
