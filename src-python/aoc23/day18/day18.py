import logging

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import *
from util.ds.grid import Grid
from util.log import log


#    #######
#    #.....#
#    ###...#
#    ..#...#
#    ..#...#
#    ###.###
#    #...#..
#    ##..###
#    .#....#
#    .######

def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    62
    """

    directions = {
        "U": NORTH,
        "D": SOUTH,
        "L": WEST,
        "R": EAST
    }

    blocks = []
    for line in lines:
        direction, steps, color = line.split()
        direction = directions[direction]
        for i in range(int(steps)):
            if not blocks:
                blocks.append(Xy(100, 100))
            else:
                blocks.append(blocks[-1].neighbor(direction))

    min_x = min(blocks, key=lambda b: b.x).x
    max_x = max(blocks, key=lambda b: b.x).x
    min_y = min(blocks, key=lambda b: b.y).y
    max_y = max(blocks, key=lambda b: b.y).y
    width = max_x - min_x + 1
    height = max_y - min_y + 1

    grid = Grid.empty(width + 2, height + 2)
    for block in blocks:
        grid.set_value(Xy(block.x - min_x + 1, block.y - min_y + 1), "#")

    log.debug(grid)

    start = Xy(0, 0)
    queue = [start]
    while queue:
        current = queue.pop(0)
        if grid.get_value(current) != ".":
            continue
        grid.set_value(current, "O")
        for n in grid.get_neighbors(current):
            if grid.get_value(n) == ".":
                queue.append(n)

    log.debug(grid)

    edges = grid.find_all("#")
    interior = grid.find_all(".")
    return len(interior) + len(edges)


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    952408144115
    """
    for line in lines:
        pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 35401
    # Star 2:
