import logging
from typing import List
from simple_logging import log

from data_input import read_all_lines
from visual import VisualGrid
from ds import Grid


# TODO Uber grid
# TODO Xy class
# TODO Search from back?
# TODO Search both nodes at the same time?

def star1(lines: List[str]):
    """
    >>> star1(read_all_lines("input-test.txt"))
    31
    """

    grid = Grid(lines)

    start_pos = grid.find_one("S")
    end_pos = grid.find_one("E")

    shortest_routes = {start_pos: 0}
    next_positions = [start_pos]

    return go(end_pos, grid, next_positions, shortest_routes)


def go(end_pos, grid, next_positions, shortest_routes):
    a_positions = set()

    while next_positions:
        pos = next_positions.pop(0)
        if end_pos and pos == end_pos:
            log.info(f"Possible shortest row: {shortest_routes[pos]}")
            continue

        if end_pos is None and grid.at_pos(pos) == "a":
            log.info(f"Possible shortest row: {shortest_routes[pos]}")
            a_positions.add(pos)
            continue

        route_len = shortest_routes[pos]
        elevation = _get_elevation(grid.at_pos(pos))

        for neighbor in def_neighbors(pos, grid.cols_count(), grid.rows_count()):
            neighbor_elevation = _get_elevation(grid.at_pos(neighbor))
            # FIXME me quick hack breaks for star 1: Use  if neighbor_elevation - elevation <= 1:
            if -1 <= neighbor_elevation - elevation:
                if _update_shortest_routes(neighbor, route_len + 1, shortest_routes):
                    next_positions.append(neighbor)
    log.info(shortest_routes)

    if end_pos:
        return shortest_routes[end_pos]
    else:
        cands = []
        for pos, route_len in shortest_routes.items():
            if pos in a_positions:
                log.info(f"Candidate: {pos}: {route_len}")
                cands.append(route_len)

        return min(cands)


def _update_shortest_routes(pos, route_len, shortest_routes):
    if pos not in shortest_routes:
        shortest_routes[pos] = route_len
        return True
    else:
        best_so_far = shortest_routes[pos]
        if route_len < best_so_far:
            shortest_routes[pos] = route_len
            return True
        return False


def _get_elevation(letter):
    if letter == "S":
        return ord('a')
    elif letter == "E":
        return ord('z')
    else:
        return ord(letter)


# TODO Move to grid
def def_neighbors(pos, width, height):
    neighbors = [
        (pos[0], pos[1] - 1),
        (pos[0] + 1, pos[1]),
        (pos[0], pos[1] + 1),
        (pos[0] - 1, pos[1]),
    ]

    return [pos for pos in neighbors if 0 <= pos[0] < height and 0 <= pos[1] < width]


def star2(lines: List[str]):
    """
    >>> star2(read_all_lines("input-test.txt"))
    29
    """

    grid = Grid(lines)

    start_pos = grid.find_one("E")
    # end_pos = grid.find_one("E")

    shortest_routes = {start_pos: 0}
    next_positions = [start_pos]

    return go(None, grid, next_positions, shortest_routes)


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    lines = read_all_lines("input.txt")
    # print(f"Star 1: {star1(lines)}")
    print(f"Star 2: {star2(lines)}")

    # Star 1: 423
    # Star 2: 416
