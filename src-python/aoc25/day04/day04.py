import logging

from util.data_io import read_input, read_test_input, timed_run
from util.ds.grid import Grid, GridCell
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    13
    """
    result = 0
    g = Grid(lines)
    for pos in g.find_all('@'):
        neighboring_rolls = len(g.get_neighbors(pos, diagonal=True, filter_fce=lambda cell: cell.value == '@'))
        if neighboring_rolls < 4:
            result += 1
    return result


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    43
    """
    result = 0
    g = Grid(lines)
    roll_positions = set(g.find_all('@'))
    while True:
        removed_positions = set()
        log.debug(f"Roll positions: {roll_positions}")
        for pos in roll_positions:
            neighboring_rolls = len(g.get_neighbors(pos, diagonal=True, filter_fce=lambda cell: cell.value == '@' and cell.pos in roll_positions))
            if neighboring_rolls < 4:
                removed_positions.add(pos)

        log.debug(f"Removing positions: {removed_positions}")
        roll_positions -= removed_positions

        if len(removed_positions) == 0:
            break
        result += len(removed_positions)

    return result


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=1547)
    timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=8948)
