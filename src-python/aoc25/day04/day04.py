import logging

from util.data_io import read_input, read_test_input, timed_run
from util.ds.grid import Grid
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    13
    """
    result = 0
    g = Grid(lines)
    for pos in g.find_all('@'):
        neighboring_rolls = len(g.get_neighbors(pos, diagonal=True, value='@'))
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
    # roll_positions = g.find_all('@')
    while True:
        g2 = Grid.empty(g.width, g.height, value='.')  # TODO Clone
        roll_positions2 = []
        result2 = 0
        for pos in g.find_all('@'):
        # for pos in roll_positions:
            neighboring_rolls = len(g.get_neighbors(pos, diagonal=True, value='@'))
            if neighboring_rolls < 4:
                result2 += 1
            else:
                g2[pos] = '@'
                roll_positions2.append(pos)

        log.debug(g2.format() + "\n")

        if result2 == 0:
            break
        g = g2
        # roll_positions = roll_positions2
        result += result2

    return result


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=1547)
    timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=8948)
