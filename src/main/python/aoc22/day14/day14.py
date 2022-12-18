import logging
from typing import List

from util.ds import Grid, Position as Pos
from util.io import read_all_lines
from util.logging import log

is_test = __name__ != "__main__"  # Only for tests


def star1(lines: List[str]):
    """
    >>> star1(read_all_lines(__file__, "input-test.txt"))
    24
    """

    return sand_fall("star1", lines)


def star2(lines: List[str]):
    """
    >>> star2(read_all_lines(__file__, "input-test.txt"))
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
        stones = [Pos.parse_swap(pos) for pos in line.split(" -> ")]
        last_stone = None
        for stone in stones:
            stone = Pos(stone.ri, stone.ci - shrink_width_by)
            if stone.ri > max_height:
                max_height = stone.ri
            if last_stone:
                grid.fill_between(last_stone, stone, "#")
            last_stone = stone

    # add floor
    floor_level = max_height + 2
    grid.fill_between(Pos(floor_level, 0), Pos(floor_level, grid.width - 1), value="#")

    log.debug(grid)

    sand_count = 0
    is_not_full = True
    while is_not_full:
        sand_count += 1
        log.debug(f"Round: {sand_count}")

        sand = Pos(0, 500 - shrink_width_by)
        is_moving = True
        while is_moving:
            at_rest = True
            moves = [Pos.down, Pos.left_down, Pos.right_down]
            for move in moves:
                if grid.at_position(move(sand)) == ".":
                    sand = move(sand)
                    at_rest = False
                    break

            if at_rest:
                is_moving = False
                grid.set_position(sand, "o")
                log.debug(grid)
                if star == "star1" and sand.ri == floor_level - 1:
                    return sand_count - 1
                if star == "star2" and sand.ri == 0:
                    return sand_count


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    lines = read_all_lines(__file__, "input.txt")
    print(f"Star 1: {star1(lines)}")
    print(f"Star 2: {star2(lines)}")

    # Star 1: 610
    # Star 2: 27194
