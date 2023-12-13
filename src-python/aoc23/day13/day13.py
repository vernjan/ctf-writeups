import logging

from util.data_io import read_input, read_test_input, timed_run
from util.ds.grid import Grid
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    405
    """
    return _solve(lines)


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    400
    """
    return _solve(lines, expected_mismatches=1)


def _solve(lines, expected_mismatches: int = 0):
    total = 0
    grid_lines = []
    for line in lines:
        if line:
            grid_lines.append(line)
            continue

        grid = Grid(grid_lines)
        log.debug(f"\n{grid}")

        total += (_find_mirror(grid, "vertical", expected_mismatches) +
                  _find_mirror(grid, "horizontal", expected_mismatches) * 100)

        grid_lines = []
    return total


def _find_mirror(grid: Grid, mirror_type: str, expected_mismatches: int = 0) -> int:
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
            if count_mismatches(const_edge, moving_edge) <= expected_mismatches:
                log.debug(f"Checking {mirror_type} mirror between {const_index}-{moving_index}")
                mirror = check_mirror(const_index, moving_index)
                if mirror:
                    mirrors.append(mirror)

        return max(mirrors, default=0)

    def count_mismatches(list1, list2) -> int:
        return sum(1 for i in range(len(list1)) if list1[i] != list2[i])

    def check_mirror(i1, i2) -> int:
        if i1 > i2:
            i1, i2 = i2, i1

        total_mismatches = 0
        mirror_half_size = (i2 - i1) // 2 + 1
        for i in range(mirror_half_size):
            values = get_values(i1 + i)
            reflected_values = get_values(i2 - i)
            total_mismatches += count_mismatches(values, reflected_values)

        if total_mismatches != expected_mismatches:
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


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 27664
    # Star 2: 33991
