import logging
from typing import List, Tuple, Set

from data_input import read_all_lines, run
from simple_logging import log


def star1(lines: List[str]):
    """
    >>> star1(read_all_lines("input-test.txt"))
    64
    """

    cubes = set()
    for cube in lines:
        x, y, z = map(int, cube.split(","))
        cubes.add((x, y, z))
    return calc_surface(cubes, exterior_only=False)


def star2(lines: List[str]):
    """
    >>> star2(read_all_lines("input-test.txt"))
    58
    """

    cubes = set()
    for cube in lines:
        x, y, z = map(int, cube.split(","))
        cubes.add((x, y, z))
    return calc_surface(cubes, exterior_only=True)


def calc_surface(cubes: Set[Tuple[int, int, int]], exterior_only):
    all_cubes = set()
    dict_xy = {}
    dict_yz = {}
    dict_zx = {}
    for x, y, z in cubes:
        all_cubes.add((x, y, z))
        _insert_value(dict_xy, (x, y), z)
        _insert_value(dict_yz, (y, z), x)
        _insert_value(dict_zx, (z, x), y)

    air_pockets_surface = 0
    if exterior_only:
        inner_cubes = _find_inner_cubes(dict_xy, dict_yz, dict_zx)
        log.debug(f"Inner cubes: {inner_cubes}")
        air_pockets = inner_cubes - all_cubes
        log.debug(f"Air pockets: {air_pockets}")

        _find_inner_cubes()

        air_pockets_surface = calc_surface(air_pockets, exterior_only=False)
        log.debug(f"Air pockets surface: {air_pockets_surface}")

    connected_sides = 0
    for x, y, z in all_cubes:
        connected_sides += _count_sides(dict_xy, (x, y), z)
        connected_sides += _count_sides(dict_yz, (y, z), x)
        connected_sides += _count_sides(dict_zx, (z, x), y)

    log.debug(f"Connected sides: {connected_sides}")
    total_sides = len(cubes) * 6
    log.debug(f"Total sides: {total_sides}")

    return total_sides - connected_sides - air_pockets_surface


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


def _find_inner_cubes(dict_xy, dict_yz, dict_zx):
    inner_cubes = set()
    for x in range(1, 20):
        for y in range(1, 20):
            for z in range(1, 20):
                if _check_is_within(dict_xy, (x, y), z) \
                        and _check_is_within(dict_yz, (y, z), x) \
                        and _check_is_within(dict_zx, (z, x), y):
                    log.debug(f"Inner cube found: {x}, {y}, {z}")
                    inner_cubes.add((x, y, z))
    return inner_cubes


def _check_is_within(d, key, value):
    if key in d:
        values = d[key]
        return min(values) < value < max(values)
    return False


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    lines = read_all_lines("input.txt")
    run("Star 1", lambda: star1(lines))
    run("Star 2", lambda: star2(lines))

    # Star 1: 4370
    # Star 2:
