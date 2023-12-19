import logging
from collections import defaultdict
from typing import Sequence

from sortedcontainers import SortedSet

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import *
from util.ds.grid import Grid
from util.log import log


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
        direction, steps, _ = line.split()
        direction = directions[direction]
        for i in range(int(steps)):
            if not blocks:
                blocks.append(Xy(0, 0))
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


# 952408144115
def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    62

    """

    # directions = {
    #     0: EAST,
    #     1: SOUTH,
    #     2: WEST,
    #     3: NORTH
    # }

    directions = {
        "U": NORTH,
        "D": SOUTH,
        "L": WEST,
        "R": EAST
    }

    # last_corner = Xy(0, 0)
    # corners = defaultdict(SortedSet)
    # corners[last_corner.x].add(last_corner.y)  # start position 0,0

    edge_count = 0
    corners = [Xy(0, 0)]
    for line in lines:  # last line returns to start
        # color = re.findall(r"#([0-9a-z]+)", line)[0]
        # steps = int(color[0:5], base=16)
        # direction = directions[int(color[-1])]
        direction, steps, _ = line.split()
        direction = directions[direction]
        steps = int(steps)
        edge_count += steps
        corners.append(corners[-1].neighbor(direction, steps))

    log.debug(f"edge_count: {edge_count}")

    min_x = min(corners, key=lambda b: b.x).x
    max_x = max(corners, key=lambda b: b.x).x
    min_y = min(corners, key=lambda b: b.y).y
    max_y = max(corners, key=lambda b: b.y).y

    log.debug(f"min_x: {min_x}, max_x: {max_x}, min_y: {min_y}, max_y: {max_y}")

    corners.sort()
    log.debug(corners)
    sorted_corners = defaultdict(list)
    for corner in corners:
        sorted_corners[corner.y].append(corner.x)

    log.debug(sorted_corners)

    # 0    #######
    # 1    #.....#
    # 2    ###...#
    # 3    ..#...#
    # 4    ..#...#
    # 5    ###.###
    # 6    #...#..
    # 7    ##..###
    # 8    .#....#
    # 9    .######

    total = 0
    last_columns = SortedSet()
    last_y = None
    for y, new_corners in sorted_corners.items():
        x_points = last_columns | new_corners
        log.debug(f"y: {y}, x_points: {x_points}, columns: {last_columns}")
        total += calc_xpoints(x_points)
        if last_y is not None:
            total += calc_rectangle_area(last_columns, y - last_y - 1)
        last_columns = x_points - (last_columns & new_corners)
        last_y = y
    return total


def calc_rectangle_area(points: Sequence[int], height) -> int:
    total_areas = 0
    for i in range(len(points)):
        if i % 2 == 1:
            width = (points[i] - points[i - 1]) + 1
            rectangle_area = height * width
            log.debug(f"rectangle_area: {rectangle_area} (width: {width}, height: {height})")
            total_areas += rectangle_area
    return total_areas


def calc_xpoints(points: Sequence[int]) -> int:
    x_points = 0
    for i in range(len(points)):
        if i % 2 == 1:
            width = (points[i] - points[i - 1]) + 1
            log.debug(f"x_points: {width}")
            x_points += width
    return x_points


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 35401
    # Star 2:
