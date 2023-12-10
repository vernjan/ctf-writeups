import logging

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xy
from util.ds.grid import Grid
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    8
    """

    north = set("S|JL")
    east = set("S-FL")
    south = set("S|F7")
    west = set("S-J7")

    def is_connected(grid: Grid, position: Xy, neighbor_position: Xy):
        my_value = grid.get_value(position)
        neighbor_value = grid.get_value(neighbor_position)
        if position.north() == neighbor_position:
            return my_value in north and neighbor_value in south
        elif position.east() == neighbor_position:
            return my_value in east and neighbor_value in west
        elif position.south() == neighbor_position:
            return my_value in south and neighbor_value in north
        else:
            return my_value in west and neighbor_value in east

    grid = Grid(lines)
    start_node = grid.find_first("S")
    loop_length = grid.find_loop_length(start_node, is_connected)
    log.debug(grid)
    return (loop_length + 1) // 2


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    10
    """
    # TBD
    for line in lines:
        pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 6828
    # Star 2:
