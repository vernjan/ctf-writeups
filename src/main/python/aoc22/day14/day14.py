import logging
from typing import List

from util.ds import Grid, Xy
from util.data_io import read_input, read_test_input
from util.log import log

is_test = __name__ != "__main__"  # Only for tests


def star1(lines: List[str]):
    """
    >>> star1(read_test_input(__file__))
    24
    """

    return sand_fall("star1", lines)


def star2(lines: List[str]):
    """
    >>> star2(read_test_input(__file__))
    93
    """

    return sand_fall("star2", lines)


def sand_fall(star, lines):
    shrink_width_by = 0
    width, height = 1000, 200
    if is_test:
        shrink_width_by = 450
        width, height = 100, 13

    grid = Grid.empty(width, height)

    max_height = 0
    for line in lines:
        stones = [Xy.parse(pos) for pos in line.split(" -> ")]
        last_stone = None
        for stone in stones:
            stone = Xy(stone.x - shrink_width_by, stone.y)
            if stone.y > max_height:
                max_height = stone.y
            if last_stone:
                grid.fill_between(last_stone, stone, "#")
            last_stone = stone

    # add floor
    floor_level = max_height + 2
    grid.fill_between(Xy(0, floor_level), Xy(grid.width - 1, floor_level), value="#")

    log.debug(grid)

    sand_count = 0
    is_not_full = True
    while is_not_full:
        sand_count += 1
        log.debug(f"Round: {sand_count}")

        sand = Xy(500 - shrink_width_by, 0)
        is_moving = True
        while is_moving:
            at_rest = True
            moves = [Xy.down, Xy.left_down, Xy.right_down]
            for move in moves:
                if grid.at(move(sand)) == ".":
                    sand = move(sand)
                    at_rest = False
                    break

            if at_rest:
                is_moving = False
                grid.set(sand, "o")
                log.debug(grid)
                if star == "star1" and sand.y == floor_level - 1:
                    return sand_count - 1
                if star == "star2" and sand.y == 0:
                    return sand_count


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    lines = read_input(__file__)
    print(f"Star 1: {star1(lines)}")
    print(f"Star 2: {star2(lines)}")

    # Star 1: 610
    # Star 2: 27194
