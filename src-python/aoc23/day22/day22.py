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
    cubes: List[Cube] = []
    for line in lines:
        points = tuple(map(Xyz.parse, line.split("~")))
        cube = Cube(points[0], points[1])
        cubes.append(cube)

    fallen_cubes = _fall(cubes)

    cubes_position_map: Dict[Xyz, Cube] = {}
    for fc in fallen_cubes:
        for p in fc.positions():
            cubes_position_map[p] = fc

    def all_upper_cubes_has_other_cube_below():
        for uc in upper_cubes:
            below_positions: Set[Xyz] = {Xyz(pos.x, pos.y, uc.p1.z - 1) for pos in uc.xy_positions()}
            below_cubes: Set[Cube] = {cubes_position_map[p] for p in below_positions if p in cubes_position_map}
            if not below_cubes - {c}:
                return False
        return True

    total = 0
    for c in fallen_cubes:
        upper_positions: Set[Xyz] = {Xyz(pos.x, pos.y, c.p2.z + 1) for pos in c.xy_positions()}
        upper_cubes: Set[Cube] = {cubes_position_map[p] for p in upper_positions if p in cubes_position_map}
        if not upper_cubes or all_upper_cubes_has_other_cube_below():
            total += 1

    return total


def _fall(cubes):
    fallen_cubes = []

    z_occupied_positions = defaultdict(set)
    for c in cubes:
        # cube falls down
        new_z_index = 1  # 1 is the lowest possible z-index
        for z, occupied_positions in reversed(z_occupied_positions.items()):
            if occupied_positions & c.xy_positions():
                new_z_index = z + 1
                break

        fallen_cube: Cube = c.z_dec(c.p1.z - new_z_index)
        fallen_cubes.append(fallen_cube)
        for z in range(fallen_cube.p1.z, fallen_cube.p2.z + 1):
            z_occupied_positions[z] |= fallen_cube.xy_positions()
    log.debug(z_occupied_positions)
    return fallen_cubes


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))

    """
    for line in lines:
        pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1:
    # Star 2:
