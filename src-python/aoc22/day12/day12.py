import logging
from typing import List

from util.data_io import read_input, read_test_input
from util.ds.grid import Grid
from util.log import log


def star1(lines: List[str]):
    """
    >>> star1(read_test_input(__file__))
    31
    """

    grid = Grid(lines)
    start_position = grid.find_first("S")
    end_positions = set(grid.find_all("E"))

    return grid.find_shortest_path(start_position, end_positions, _has_access_up)


def star2(lines: List[str]):
    """
    >>> star2(read_test_input(__file__))
    29
    """

    grid = Grid(lines)
    start_position = grid.find_first("E")
    end_positions = set(grid.find_all("a"))

    return grid.find_shortest_path(start_position, end_positions, _has_access_down)


def _has_access_up(grid, position, neighbor):
    elevation = _get_elevation(grid.get_value(position))
    neighbor_elevation = _get_elevation(grid.get_value(neighbor))
    return neighbor_elevation - elevation <= 1


def _has_access_down(grid, position, neighbor):
    elevation = _get_elevation(grid.get_value(position))
    neighbor_elevation = _get_elevation(grid.get_value(neighbor))
    return neighbor_elevation - elevation >= -1


def _get_elevation(letter):
    if letter == "S":
        return ord('a')
    elif letter == "E":
        return ord('z')
    else:
        return ord(letter)


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    lines = read_input(__file__)
    print(f"Star 1: {star1(lines)}")
    print(f"Star 2: {star2(lines)}")

    # Star 1: 423
    # Star 2: 416
