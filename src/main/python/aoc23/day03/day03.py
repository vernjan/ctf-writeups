import logging

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import WEST, EAST, Direction, Xy
from util.ds.grid import Grid
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    4361
    """
    return solve(lines)[0]


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    467835
    """
    return solve(lines)[1]


def solve(lines: list[str]):
    def get_number_part(start_pos: Xy, direction: Direction) -> str:
        number_part = ""
        for cell in grid.get_cells_from(start_pos, direction, pattern="\\d"):
            visited.add(cell.pos)
            number_part += cell.value
        return number_part

    grid = Grid(lines)
    total_star1 = 0
    total_star2 = 0
    visited = set()
    for pos in grid.find_all_re("[^0-9.]"):
        log.debug(f"Checking starting position {pos}")
        numbers = []  # for star 2
        for n in grid.get_neighbors(pos, diagonal=True):
            n_val = grid.get_cell(n).value
            if n_val.isdigit() and n not in visited:
                visited.add(n)
                number = int(get_number_part(n.west(), WEST)[::-1] + n_val + get_number_part(n.east(), EAST))
                log.debug(f"Found number {number}")
                total_star1 += number
                numbers.append(number)
        if len(numbers) == 2:
            total_star2 += numbers[0] * numbers[1]

    return total_star1, total_star2


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 556057
    # Star 2: 82824352
