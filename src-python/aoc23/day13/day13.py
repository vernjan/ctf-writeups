import logging

from util.data_io import read_input, read_test_input, timed_run
from util.ds.grid import Grid
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    405
    """

    total = 0
    grid_lines = []
    for line in lines:
        if line:
            grid_lines.append(line)
            continue

        grid = Grid(grid_lines)
        log.debug(f"\n{grid}")

        v_mirror = _find_mirror(grid, "vertical")
        if v_mirror:
            total += v_mirror
        h_mirror = _find_mirror(grid, "horizontal")
        if h_mirror:
            total += 100 * h_mirror

        grid_lines = []

    return total


def _find_mirror(grid: Grid, mirror_type: str) -> int:
    def find_mirror_edges():
        # left->right, right->left (or top->bottom, bottom->top)
        return max(
            find_mirror_edge(0, size - 2, -2),
            find_mirror_edge(size - 1, 1, 2)
        )

    def find_mirror_edge(const_index, start_index, step):
        mirrors = []
        const_edge = get_values(const_index)
        for moving_index in range(start_index, const_index, step):
            moving_edge = get_values(moving_index)
            if const_edge == moving_edge:
                log.debug(f"Checking {mirror_type} mirror between {const_index}-{moving_index}")
                mirror = check_mirror(const_index, moving_index)
                if mirror:
                    mirrors.append(mirror)

        return max(mirrors, default=0)

    def check_mirror(i1, i2) -> int:
        if i1 > i2:
            i1, i2 = i2, i1

        mirror_half_size = (i2 - i1) // 2 + 1
        for i in range(mirror_half_size):
            if get_values(i1 + i) != get_values(i2 - i):
                return 0

        result = (i2 + i1) // 2 + 1
        log.debug(f"Mirror found: {result}")
        return result

    if mirror_type == "vertical":
        size = grid.width
        get_values = grid.get_col_values
    else:
        size = grid.height
        get_values = grid.get_row_values

    return find_mirror_edges()


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

    # Star 1: 27664
    # Star 2:
