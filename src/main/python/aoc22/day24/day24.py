import logging
from itertools import count
from typing import List

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xy
from util.ds.grid import Grid
from util.log import log


def star1(lines: List[str]):
    """
    >>> star1(read_test_input(__file__))
    18
    """

    grid = Grid(lines)
    start_pos = grid.find_first(".")
    exit_pos = grid.find_last(".")

    for time_counter in count(1):
        log.debug(f"Time: {time_counter}")
        log.debug(grid)

        new_grid = Grid.empty(grid.width, grid.height)
        for cell in grid.get_all_cells():
            if cell.value == "#":
                new_grid.set_value(cell.pos, "#")
            else:
                for value in cell.value:
                    if value == ".":
                        break
                    new_pos = _move_blizzard(cell.pos, value, grid.width, grid.height)
                    target_cell = new_grid.get_cell(new_pos)
                    if target_cell.value == ".":
                        target_cell.value = []
                    target_cell.value.append(value)

        grid = new_grid
        if time_counter == 1000:
            break

    # Grid - 120x25 (600), example 4x6 (12)
    # Context - key: pos + time%LCM: time
    # Can move?
    # YES - BFS all directions (save pos+time, be able to restore any time in a single step)
    # NO - wait

    pass


# TODO optimization: Move by X steps
def _move_blizzard(pos: Xy, direction: str, width: int, height: int) -> Xy:
    if direction == "^":
        return Xy(pos.x, height - 2 if pos.y == 1 else pos.y - 1)
    elif direction == ">":
        return Xy(1 if pos.x == width - 2 else pos.x + 1, pos.y)
    elif direction == "v":
        return Xy(pos.x, 1 if pos.y == height - 2 else pos.y + 1)
    elif direction == "<":
        return Xy(width - 2 if pos.x == 1 else pos.x - 1, pos.y)
    else:
        assert False, "What???"


def star2(lines: List[str]):
    """
    >>> star2(read_test_input(__file__))

    """

    pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1:
    # Star 2:
