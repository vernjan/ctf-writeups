import logging

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Direction, WEST, EAST
from util.log import log
from util.ds.grid import Grid, GridCell


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    4361
    """
    grid = Grid(lines)
    total = 0
    visited = set()
    for pos in grid.find_all_re("[^0-9.]"):
        log.debug(f"Checking starting position {pos}")
        for n in grid.get_neighbors(pos, diagonal=True):
            n_val = grid.get_cell(n).value
            if n_val.isdigit() and n not in visited:
                visited.add(n)
                log.debug(f"Found {n_val}")
                number = n_val
                for x in grid.get_cells_from(n.west(), WEST):
                    if x.value.isdigit():
                        visited.add(x.pos)
                        number = x.value + number
                    else:
                        break
                for x in grid.get_cells_from(n.east(), EAST):
                    if x.value.isdigit():
                        visited.add(x.pos)
                        number = number + x.value
                    else:
                        break
                log.debug(f"Found number {number}")
                total += int(number)

    return total


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    467835
    """
    grid = Grid(lines)
    log.debug(grid)
    start_positions = grid.find_all("*")
    total = 0
    visited = set()
    for sp in start_positions:
        log.debug(f"Checking around {sp}")
        numbers = []
        for n_pos in grid.get_neighbors(sp, diagonal=True):
            log.debug(n_pos)
            n = grid.get_cell(n_pos)
            if n.value.isdigit() and n_pos not in visited:
                visited.add(n_pos)
                log.debug(f"Found {n.value}")
                number = n.value
                for x in grid.get_cells_from(n_pos.west(), WEST):
                    if x.value.isdigit():
                        visited.add(x.pos)
                        number = x.value + number
                    else:
                        break
                for x in grid.get_cells_from(n_pos.east(), EAST):
                    if x.value.isdigit():
                        visited.add(x.pos)
                        number = number + x.value
                    else:
                        break
                log.debug(f"Found number {number}")
                numbers.append(number)
        if len(numbers) == 2:
            log.debug(f"Found numbers {numbers}")
            total += int(numbers[0]) * int(numbers[1])

    return total


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 556057
    # Star 2: 82824352
