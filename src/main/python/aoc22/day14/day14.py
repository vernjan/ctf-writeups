import logging
from typing import List
from simple_logging import log

from data_input import read_all_lines
from ds import Grid, Position as Pos


def star1(lines: List[str]):
    """
    >>> star1(read_all_lines("input-test.txt"))
    24
    """

    is_test = __name__ != "__main__"  # Only for tests

    grid = Grid.empty(width=11, height=13)

    for line in lines:
        positions = [Pos.parse_swap(pos) for pos in line.split(" -> ")]
        last_position = None
        for pos in positions:
            if is_test:
                pos = Pos(pos.ri, pos.ci - 493)
            if last_position:
                grid.fill_between(last_position, pos, "#")
            last_position = pos

    log.debug(grid)


def star2(lines: List[str]):
    """
    >>> star2(read_all_lines("input-test.txt"))
    'TODO'
    """

    pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    lines = read_all_lines("input.txt")
    print(f"Star 1: {star1(lines)}")
    print(f"Star 2: {star2(lines)}")

    # Star 1:
    # Star 2:
