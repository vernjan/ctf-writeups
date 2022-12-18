import logging
from typing import List

from util.io import read_all_lines, timed_run
from util.ds import Xyz
from util.logging import log


def star1(lines: List[str]):
    """
    >>> star1(read_all_lines(__file__, "input-test.txt"))
    64
    """

    cubes = set()
    dict_xy = {}
    dict_yz = {}
    dict_zx = {}
    for cube in lines:
        x, y, z = map(int, cube.split(","))
        cubes.add((x, y, z))
        _insert_value(dict_xy, (x, y), z)
        _insert_value(dict_yz, (y, z), x)
        _insert_value(dict_zx, (z, x), y)

    connected_sides = 0
    for x, y, z in cubes:
        connected_sides += _count_sides(dict_xy, (x, y), z)
        connected_sides += _count_sides(dict_yz, (y, z), x)
        connected_sides += _count_sides(dict_zx, (z, x), y)

    return len(cubes) * 6 - connected_sides


def star2(lines: List[str]):
    """
    >>> star2(read_all_lines(__file__, "input-test.txt"))
    58
    """

    cubes = set(map(Xyz.parse, lines))

    surface_area = 0
    visited_cubes = set()
    q = [Xyz(0, 0, 0)]

    while q:
        cube = q.pop(0)
        if cube in visited_cubes:
            continue

        visited_cubes.add(cube)
        for n in cube.neighbors(["side"]):
            if -1 <= n.x <= 21 and -1 <= n.y <= 21 and -1 <= n.z <= 21:
                if n in cubes:
                    surface_area += 1
                else:
                    q.append(n)

    return surface_area


def _insert_value(d, key, value):
    if key not in d:
        d[key] = {value}
    else:
        d[key].add(value)


def _count_sides(d, key, value):
    count = 0
    sides = d[key]
    if value - 1 in sides:
        count += 1
    if value + 1 in sides:
        count += 1
    return count


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    lines = read_all_lines(__file__, "input.txt")
    timed_run("Star 1", lambda: star1(lines))
    timed_run("Star 2", lambda: star2(lines))

    # Star 1: 4370
    # Star 2: 2458
