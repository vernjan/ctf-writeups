import logging

import matplotlib

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xy, Rectangle, Line, SOUTH_EAST
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

    # border tiles
    border = set()
    start_point = points[0]
    for end_point in points[1:]:
        line = Line.of(start_point, end_point)
        border.update(line.points())
        start_point = end_point
    log.debug(len(border))
    log.debug(border)

    # outer border tiles
    min_x, min_y, max_x, max_y = (100_000, 100_000, 0, 0)
    for p in points:
        if p.x < min_x:
            min_x = p.x
        if p.x > max_x:
            max_x = p.x
        if p.y < min_y:
            min_y = p.y
        if p.y > max_y:
            max_y = p.y

    min_x -= 1
    max_x += 1
    min_y -= 1
    max_y += 1

    outer_border = set()
    visited = set()
    top_left_point = Xy(min_x, min_y)
    queue = [top_left_point]
    while queue:
        point = queue.pop()
        visited.add(point)
        if not outer_border:
            next_point = point.neighbor(SOUTH_EAST)
            if next_point in border:
                outer_border.add(point)
            else:
                queue.append(next_point)
        if outer_border and point not in border:
            neighbors = [n for n in point.neighbors()
                         if min_x <= n.x <= max_x and min_y <= n.y <= max_y and n not in visited]
            for neighbor in neighbors:
                if neighbor in border:
                    outer_border.add(point)
                else:
                    if len([nn for nn in neighbor.neighbors(diagonal=True) if nn in border]) > 0:
                        queue.append(neighbor)
    log.info(len(outer_border))
    log.debug(outer_border)

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

    # _visualize(points, outer_border)

    biggest_rectangle = 0
    for i, p1 in enumerate(points[:-1]):
        for p2 in points[i + 1:]:
            rectangle = Rectangle.of(p1, p2)
            area = rectangle.area()
            if area > biggest_rectangle:
                valid = True
                for ob in outer_border:
                    if rectangle.has(ob):
                        valid = False
                        break
                if valid:
                    log.info(f"Rect found: {area}")
                    biggest_rectangle = area
    return biggest_rectangle


def _visualize(border_lines: list[Xy], outer_border_points: set[Xy]):
    matplotlib.use("TkAgg")
    import matplotlib.pyplot as plt

    plt.figure(figsize=(10, 8))

    # border
    xs = [p.x for p in border_lines]
    ys = [p.y for p in border_lines]
    plt.plot(xs, ys, marker=',', linestyle='-', linewidth=0.8, color='blue')  # marker=',' is a single pixel marker

    # outer border
    xs2 = [p.x for p in outer_border_points]
    ys2 = [p.y for p in outer_border_points]
    plt.plot(xs2, ys2, marker='o', linestyle='None', markersize=0.8, color='red')

    plt.title("AoC Day 9")
    plt.axis('equal')
    plt.grid(True)
    plt.show()


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=4744899849)
    timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=1540192500)
