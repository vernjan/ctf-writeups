import logging
from typing import Set, List, Tuple

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xy
from util.ds.grid import Grid
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    8
    """
    grid = Grid(lines)
    loop_length = len(_find_main_loop(grid))
    return (loop_length + 1) // 2


def star2(lines: list[str], s_replacement: str):
    """
    >>> star2(read_test_input(__file__, "input-test2.txt"), "7")
    10
    """
    closed_corners = {
        "J": "NW",
        "L": "NE",
        "F": "SE",
        "7": "SW",
    }

    # direction -> bend flips, i.e. if we go north, and we stand on J, we exit on east
    location_flips = {
        "N": {"J": "E", "L": "W"},
        "E": {"L": "S", "F": "N"},
        "S": {"F": "W", "7": "E"},
        "W": {"7": "N", "J": "S"}
    }

    grid = Grid(lines)
    main_loop: Set[Xy] = _find_main_loop(grid)
    grid.set_value(grid.find_first("S"), s_replacement)
    start_position = Xy(0, 0)
    visited = set()
    queue: List[Tuple[Xy, str]] = [(start_position, "NW")]
    while queue:
        current_pos, current_loc = queue.pop(0)  # position in grid, location in cell
        if current_pos in visited:
            continue
        visited.add(current_pos)
        current_val = grid.get_value(current_pos)

        if current_pos not in main_loop:
            open_directions = "NESW"
        # crawling around the main loop
        elif current_val == "-":
            open_directions = "EW" + current_loc[0]
        elif current_val == "|":
            open_directions = "NS" + current_loc[1]
        else:
            # one of J, L, F, 7
            if closed_corners[current_val] == current_loc:  # if we are in the "closed" corner
                open_directions = current_loc
            else:
                open_directions = "NESW"

        # visualization
        grid.set_value(current_pos, "x" if current_pos in main_loop else "o")

        for neighbor_pos in grid.get_neighbors(current_pos):
            if neighbor_pos not in visited:
                if current_pos.north() == neighbor_pos:
                    neighbor_dir = "N"
                    neighbor_loc = list("S?")
                elif current_pos.east() == neighbor_pos:
                    neighbor_dir = "E"
                    neighbor_loc = list("?W")
                elif current_pos.south() == neighbor_pos:
                    neighbor_dir = "S"
                    neighbor_loc = list("N?")
                elif current_pos.west() == neighbor_pos:
                    neighbor_dir = "W"
                    neighbor_loc = list("?E")
                else:
                    raise ValueError(f"Unexpected neighbor position: {neighbor_pos}")

                loc_index = neighbor_loc.index("?")
                if closed_corners.get(current_val) == current_loc:  # we're in a closed corner, so no side flipping
                    neighbor_loc[loc_index] = current_loc[loc_index]
                else:
                    neighbor_loc[loc_index] = location_flips[neighbor_dir].get(current_val, current_loc[loc_index])

                if neighbor_dir in open_directions:
                    queue.append((neighbor_pos, "".join(neighbor_loc)))

    log.debug(f"\n{grid}")

    return grid.width * grid.height - len(visited)


def _find_main_loop(grid: Grid, trace=False) -> Set[Xy]:
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
        elif position.west() == neighbor_position:
            return my_value in west and neighbor_value in east
        else:
            raise ValueError(f"Unexpected neighbor position: {neighbor_position}")

    start_node = grid.find_first("S")
    loop_nodes = grid.find_loop(start_node, is_connected, trace)
    log.debug(grid)
    return loop_nodes


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__), "J"), )

    # Star 1: 6828
    # Star 2: 459
