import logging

from util.data_io import read_input, read_test_input, timed_run
from util.ds.grid import Grid
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    13
    """
    g = Grid(lines)
    return _remove_rolls(g, multi_round=False)


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    43
    """
    g = Grid(lines)
    result = 0
    while True:
        round_result = _remove_rolls(g, multi_round=True)
        result += round_result
        if round_result == 0:
            break

    return result


def _remove_rolls(g: Grid[str], multi_round: bool) -> int:
    removed_rolls_count = 0
    for pos in g.find_all('@'):
        neighboring_rolls = len(g.get_neighbors(pos, diagonal=True, filter_fce=lambda cell: cell.value == '@'))
        if neighboring_rolls < 4:
            if multi_round:
                g[pos].value = '.'
            removed_rolls_count += 1
    return removed_rolls_count


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=1547)
    timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=8948)
