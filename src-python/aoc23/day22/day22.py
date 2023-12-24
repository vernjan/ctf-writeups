import logging
from collections import defaultdict
from typing import Dict, List

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xyz, Cube
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    5
    """
    cubes: List[Cube] = []
    cubes_positions: Dict[Xyz, Cube] = {}
    for line in lines:
        points = tuple(map(Xyz.parse, line.split("~")))
        cube = Cube(points[0], points[1])
        cubes.append(cube)
        for p in cube.positions():
            cubes_positions[p] = cube

    fallen_cubes = _fall(cubes)
    log.debug(fallen_cubes)


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
    assert list(z_occupied_positions)[-1] == 6  # TODO remove me, just for test data
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
