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
        else:
            grid = Grid(grid_lines)
            log.debug("GRID:")

            v_mirror = find_mirror(grid, "vertical")
            h_mirror = find_mirror(grid, "horizontal")

            if v_mirror > 0:
                total += v_mirror
            if h_mirror > 0:
                total += 100 * h_mirror

            grid_lines = []

    return total


def find_mirror(grid: Grid, mirror_type: str) -> int:
    if mirror_type == "vertical":
        size = grid.width
        get_values = grid.get_col_values
    else:
        size = grid.height
        get_values = grid.get_row_values

    opposite_side_index = None
    for li in range(size - 1):  # TODO size // 2 + 1
        left = get_values(li)  # left or top
        # right = get_values(size - 1)
        # if left == right:
        #     for mi in range(li, li, -1):  # TODO could step by 2

        ri_start_from = opposite_side_index if opposite_side_index else size - 1
        # ri_end = li
        # if opposite_side_index:
        ri_end = size - 2 if li > 0 and not opposite_side_index else li
        for ri in range(ri_start_from, ri_end, -1):  # TODO could step by 2
            right = get_values(ri)
            if left == right:
                opposite_side_index = ri
                if li + 1 == opposite_side_index:
                    log.debug(f"{mirror_type} mirror found at {li + 1}")
                    return li + 1
                break
            else:
                opposite_side_index = None

    return -1


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


    # opposite_side_index = None
    # for li in range(size - 1):  # TODO size // 2 + 1
    #     left = get_values(li)  # left or top
    #
    #
    #     ri_start_from = opposite_side_index if opposite_side_index else size - 1
    #     for ri in range(ri_start_from, li, -1):  # TODO could step by 2
    #         right = get_values(ri)
    #         if left == right:
    #             opposite_side_index = ri
    #             if li + 1 == opposite_side_index:
    #                 log.debug(f"{mirror_type} mirror found at {li + 1}")
    #                 return li + 1
    #             break
    #         else:
    #             opposite_side_index = None
    #
    # return -1