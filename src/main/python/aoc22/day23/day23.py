import logging
from typing import List
import math

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import NORTH, EAST, SOUTH, WEST, NORTH_EAST, SOUTH_EAST, SOUTH_WEST, NORTH_WEST, Direction
from util.ds.grid import Grid
from util.log import log

DIRECTIONS = [NORTH, SOUTH, WEST, EAST]

DIRECTIONS_IN_SIGHT = {
    NORTH: [NORTH_WEST, NORTH, NORTH_EAST],
    EAST: [NORTH_EAST, EAST, SOUTH_EAST],
    SOUTH: [SOUTH_EAST, SOUTH, SOUTH_WEST],
    WEST: [SOUTH_WEST, WEST, NORTH_WEST],
}


def star1(lines: List[str], padding_size, max_rounds):
    """
    >>> star1(read_test_input(__file__), 3, 10)
    110
    """

    return simulate(lines, max_rounds, padding_size)[1]


def star2(lines: List[str], padding_size, max_rounds):
    """
    >>> star2(read_test_input(__file__), 3, math.inf)
    20
    """

    return simulate(lines, max_rounds, padding_size)[0]


def simulate(lines, max_rounds, padding_size):
    grid = Grid(lines, padding_size)
    log.debug(grid)
    round_dir = NORTH
    round_number = 1
    while round_number <= max_rounds:
        proposed_positions = {}

        for elf_position in grid.find_all("#"):
            if _check_all_empty(grid, grid.get_neighbors(elf_position, diagonal=True)):
                continue

            elf_dir = round_dir
            for _ in range(len(DIRECTIONS)):
                positions_in_sight = [elf_position.neighbor(dir) for dir in (DIRECTIONS_IN_SIGHT[elf_dir])]
                if _check_all_empty(grid, positions_in_sight):
                    proposed_position = elf_position.neighbor(elf_dir)
                    if proposed_position not in proposed_positions:
                        proposed_positions[proposed_position] = [elf_position]
                    else:
                        proposed_positions[proposed_position].append(elf_position)
                    break
                elf_dir = _get_next_direction(elf_dir)

        if not proposed_positions:
            break

        accepted_positions = {proposed: elves[0] for proposed, elves in proposed_positions.items() if len(elves) == 1}
        for new_position, old_position in accepted_positions.items():
            grid.set_value(old_position, ".")
            grid.set_value(new_position, "#")

        log.debug(str(grid) + "\n")
        round_number += 1
        round_dir = _get_next_direction(round_dir)

    elves_positions = grid.find_all("#")
    return round_number, _count_empty(elves_positions, grid)


def _get_next_direction(start_from: Direction) -> Direction:
    index = DIRECTIONS.index(start_from)
    return DIRECTIONS[(index + 1) % len(DIRECTIONS)]


def _check_all_empty(grid, positions):
    return all(map(lambda pos: grid.get_value(pos) == ".", positions))


def _count_empty(elves, grid):
    min_x, min_y = grid.width, grid.height
    max_x, max_y = 0, 0
    for cell in grid.get_all_cells():
        if cell.value == "#":
            min_x = min(min_x, cell.pos.x)
            min_y = min(min_y, cell.pos.y)
            max_x = max(max_x, cell.pos.x)
            max_y = max(max_y, cell.pos.y)
    return (max_x - min_x + 1) * (max_y - min_y + 1) - len(elves)


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__), 10, 10))
    timed_run("Star 2", lambda: star2(read_input(__file__), 50, math.inf))

    # Star 1: 3987
    # Star 2: 938
