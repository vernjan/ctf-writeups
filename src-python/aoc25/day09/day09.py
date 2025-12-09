import logging

import matplotlib

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xy, Rectangle, Line
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    50
    """
    points = [Xy.parse(line) for line in lines]

    biggest_rectangle = 0
    for i, p1 in enumerate(points[:-1]):
        for p2 in points[i + 1:]:
            area = Rectangle.of(p1, p2).area()
            if area > biggest_rectangle:
                biggest_rectangle = area
    return biggest_rectangle


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    24
    """
    points = [Xy.parse(line) for line in lines]
    points.append(Xy.parse(lines[0]))  # close the loop

    # _visualize(points)

    # borders tiles
    tiles = set()
    start_point = points[0]
    for end_point in points[1:]:
        line = Line.of(start_point, end_point)
        tiles.update(line.points())
        start_point = end_point

    log.debug(tiles)



    # h_lines: dict[int, list[Line]] = defaultdict(list)
    # v_lines: dict[int, list[Line]] = defaultdict(list)
    #
    # start_point = points[0]
    # for end_point in points[1:]:
    #     line = Line.of(start_point, end_point)
    #     if line.is_horizontal():
    #         h_lines[start_point.y].append(line)
    #     else:
    #         v_lines[start_point.x].append(line)
    #     start_point = end_point
    #
    # def within_border(p: Xy, dir: Direction):
    #     match dir:
    #         case EAST:
    #             v_lines[p.x]
    #         case SOUTH:
    #         case WEST:
    #         case NORTH:

    # fill the borders
    # queue = set(points[0].south_east())

    biggest_rectangle = 0
    for i, p1 in enumerate(points[:-1]):
        for p2 in points[i + 1:]:
            rectangle = Rectangle.of(p1, p2)

            area = rectangle.area()
            if area > biggest_rectangle:
                biggest_rectangle = area
    return biggest_rectangle


def _visualize(points: list[Xy]):
    matplotlib.use("TkAgg")
    import matplotlib.pyplot as plt

    xs = [p.x for p in points]
    ys = [p.y for p in points]
    plt.figure(figsize=(10, 8))

    plt.plot(xs, ys, marker=',', linestyle='-', linewidth=0.8, color='blue')  # marker=',' is a single pixel marker
    plt.title("AoC Day 9")
    plt.axis('equal')
    plt.grid(True)
    plt.show()


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=4744899849)
    timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=None)
