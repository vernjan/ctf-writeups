import dataclasses
import logging
from collections import defaultdict
from typing import Set, Iterable

from sortedcontainers import SortedSet

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import *
from util.ds.grid import Grid
from util.log import log


@dataclasses.dataclass(frozen=True)
class Rectangle:
    x1: int
    x2: int
    y1: int = dataclasses.field(hash=False)

    def __repr__(self):
        return f"[{self.x1}-{self.x2};{self.y1}]"


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

    directions = {
        0: EAST,
        1: SOUTH,
        2: WEST,
        3: NORTH
    }

    corners = [Xy(0, 0)]
    for line in lines[:-1]:  # last line returns to start
        color = re.findall(r"#([0-9a-z]+)", line)[0]
        steps = int(color[0:5], base=16)
        direction = directions[int(color[-1])]
        corners.append(corners[-1].neighbor(direction, steps))

    corners.sort()
    sorted_corners = defaultdict(list)
    for corner in corners:
        sorted_corners[corner.y].append(corner.x)

    total_area = 0
    open_rectangles: Set[Rectangle] = set()
    for y, new_corners in sorted_corners.items():
        open_points = _rectangles2points(open_rectangles)
        points = (open_points | new_corners) - (open_points & new_corners)
        rectangles = _points2rectangles(points, y)
        finished_rectangles = open_rectangles - rectangles
        new_rectangles = rectangles - open_rectangles
        overlaps = _calculate_overlaps(finished_rectangles, new_rectangles)
        log.debug(
            f"y: {y}, corners: {corners}, rectangles: {rectangles},"
            f" finished_rectangles: {finished_rectangles}, new_rectangles: {new_rectangles}, overlap: {overlaps}")
        total_area -= overlaps
        total_area += _calc_rectangle_areas(finished_rectangles, y)
        open_rectangles = rectangles
    return total_area


def _points2rectangles(top_corners: SortedSet[int], y: int) -> Set[Rectangle]:
    result = set()
    for i in range(0, len(top_corners), 2):
        result.add(Rectangle(top_corners[i], top_corners[i + 1], y))
    return result


def _rectangles2points(rectangles: Set[Rectangle]) -> SortedSet[int]:
    result = SortedSet()
    for r in rectangles:
        result.add(r.x1)
        result.add(r.x2)
    return result


def _calculate_overlaps(rectangles1, rectangles2):
    result = 0
    for r1 in rectangles2:
        for r2 in rectangles1:
            total_size = (r1.x2 - r1.x1) + (r2.x2 - r2.x1) + 2
            size = max(r1.x2, r2.x2) - min(r1.x1, r2.x1) + 1
            if size < total_size:
                result += total_size - size
    return result


def _calc_rectangle_areas(rectangles: Iterable[Rectangle], y) -> int:
    result = 0
    for r in rectangles:
        width = r.x2 - r.x1 + 1
        height = y - r.y1 + 1
        area = height * width
        log.debug(f"rectangle_area: {area} (width: {width}, height: {height})")
        result += area
    return result


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 35401
    # Star 2: 48020869073824
