import logging

import matplotlib

matplotlib.use('TkAgg')
import matplotlib.pyplot as plt

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xy, calc_rectangle_area
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
            area = calc_rectangle_area(p1, p2)
            if area > biggest_rectangle:
                biggest_rectangle = area
    return biggest_rectangle


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    24
    """
    points = [Xy.parse(line) for line in lines]

    _visualize(points)

    biggest_rectangle = 0
    for i, p1 in enumerate(points[:-1]):
        for p2 in points[i + 1:]:
            area = calc_rectangle_area(p1, p2)
            if area > biggest_rectangle:
                biggest_rectangle = area
    return biggest_rectangle


def _visualize(points: list[Xy]):
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
