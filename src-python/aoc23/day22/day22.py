import logging
from collections import defaultdict
from typing import Dict, List, Set

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xyz, Cube
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    5
    """
    cubes = _fall(_parse_cubes(lines))

    cubes_position_map = get_cubes_position_map(cubes)

    def all_upper_cubes_has_other_support():
        for uc in upper_cubes:
            below_cubes = _get_cubes_below(uc, cubes_position_map)
            if len(below_cubes) == 1:
                return False
        return True

    total = 0
    for c in cubes:
        upper_cubes = _get_cubes_above(c, cubes_position_map)
        if not upper_cubes or all_upper_cubes_has_other_support():
            total += 1

    return total


def get_cubes_position_map(cubes):
    cubes_position_map: Dict[Xyz, Cube] = {}
    for c in cubes:
        for p in c.positions:
            cubes_position_map[p] = c
    return cubes_position_map


def _get_cubes_above(c, cubes_position_map):
    positions_above: Set[Xyz] = {Xyz(pos.x, pos.y, c.p2.z + 1) for pos in c.xy_positions}
    return {cubes_position_map[p] for p in positions_above if p in cubes_position_map}


def _get_cubes_below(c, cubes_position_map):
    positions_below: Set[Xyz] = {Xyz(pos.x, pos.y, c.p1.z - 1) for pos in c.xy_positions}
    return {cubes_position_map[p] for p in positions_below if p in cubes_position_map}


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    7
    """
    cubes = _fall(_parse_cubes(lines))
    cubes_position_map = get_cubes_position_map(cubes)

    total = 0
    for bottom_cube in sorted(cubes, key=lambda c: c.p1.z):  # TODO no sorting requird I think
        queue = []
        cpm = cubes_position_map.copy()
        queue.extend(_get_cubes_above(bottom_cube, cpm))
        while queue:
            # queue.sort(key=lambda c: c.p1.z)
            cube = queue.pop(0)
            if cube.p1 not in cpm:
                continue  # already processed
            cubes_below = _get_cubes_below(cube, cpm)
            if len(cubes_below) <= 1:
                total += 1
                queue.extend(_get_cubes_above(cube, cpm))
                for p in cube.positions:
                    del cpm[p]

    return total


def _parse_cubes(lines):
    cubes: List[Cube] = []
    for line in lines:
        points = tuple(map(Xyz.parse, line.split("~")))
        cube = Cube(points[0], points[1])
        cubes.append(cube)
    return cubes


def _fall(cubes):
    fallen_cubes = []

    z_occupied_positions = defaultdict(set)
    for c in sorted(cubes, key=lambda c: c.p1.z):
        # cube falls down
        new_z_index = 1  # 1 is the lowest possible z-index
        for z, occupied_positions in reversed(z_occupied_positions.items()):
            if occupied_positions & c.xy_positions:
                new_z_index = z + 1
                break

        fallen_cube: Cube = c.z_dec(c.p1.z - new_z_index)
        fallen_cubes.append(fallen_cube)
        for z in range(fallen_cube.p1.z, fallen_cube.p2.z + 1):
            z_occupied_positions[z] |= fallen_cube.xy_positions
    return fallen_cubes


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 534
    # Star 2:
