import logging
import math

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xy
from util.ds.grid import Grid
from util.log import log


class PositionMemory:
    def __init__(self, max_wait):
        self.max_wait = max_wait
        self.mem = {}

    def store_if_better(self, pos, time):
        time_key = time % self.max_wait
        key = (pos, time_key)
        if key not in self.mem or time < self.mem[key]:
            self.mem[key] = time
            return True
        return False


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    18
    """

    grid = Grid(lines)
    start_pos = grid.find_first(".")
    exit_pos = grid.find_last(".")
    max_wait = math.lcm(grid.width - 2, grid.height - 2)  # blizzard positions are exactly the same after max_wait

    log.info("Pre-generating all blizzard states ..")
    blizzard_states = _generate_all_blizzard_states(grid, max_wait)

    return _go(start_pos, exit_pos, 0, max_wait, blizzard_states)


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    54
    """

    grid = Grid(lines)
    start_pos = grid.find_first(".")
    exit_pos = grid.find_last(".")
    max_wait = math.lcm(grid.width - 2, grid.height - 2)  # blizzard positions are exactly the same after max_wait

    log.info("Pre-generating all blizzard states ..")
    blizzard_states = _generate_all_blizzard_states(grid, max_wait)

    trip1_time = _go(start_pos, exit_pos, 0, max_wait, blizzard_states)
    trip2_time = _go(exit_pos, start_pos, trip1_time, max_wait, blizzard_states)
    trip3_time = _go(start_pos, exit_pos, trip2_time, max_wait, blizzard_states)

    return trip3_time


def _go(start_pos, exit_pos, start_time, max_wait, blizzard_states):
    log.info("Looking for the shortest path ..")
    mem = PositionMemory(max_wait)
    queue = [(start_pos, start_time)]
    shortest_time = math.inf
    while queue:
        pos, time = queue.pop(0)

        if time >= shortest_time:
            continue

        if pos == exit_pos:
            log.info(f"Exit position reached in: {time}")
            shortest_time = time
            continue

        if not mem.store_if_better(pos, time):
            continue

        for delta_time in range(1, max_wait + 1):
            grid = blizzard_states[(time + delta_time) % max_wait]

            for neighbor in grid.get_neighbors(pos):
                if grid.get_value(neighbor) == ".":
                    queue.append((neighbor, time + delta_time))

            if grid.get_value(pos) != ".":  # blizzard is here, we must move
                break
    return shortest_time


def _generate_all_blizzard_states(initial_grid: Grid, max_wait: int) -> dict[int, Grid]:
    blizzard_states = {}
    grid = initial_grid
    for time in range(max_wait):
        blizzard_states[time] = grid
        new_grid = Grid.empty(grid.width, grid.height)
        for cell in grid.get_all_cells():
            if cell.value == "#":
                new_grid.set_value(cell.pos, "#")
            else:
                for value in cell.value:
                    if value == ".":
                        break
                    new_pos = _move_blizzard(cell.pos, value, grid.width, grid.height)
                    target_cell = new_grid.get_cell(new_pos)
                    if target_cell.value == ".":
                        target_cell.value = []
                    target_cell.value.append(value)

        grid = new_grid
    return blizzard_states


def _move_blizzard(pos: Xy, direction: str, width: int, height: int) -> Xy:
    if direction == "^":
        return Xy(pos.x, height - 2 if pos.y == 1 else pos.y - 1)
    elif direction == ">":
        return Xy(1 if pos.x == width - 2 else pos.x + 1, pos.y)
    elif direction == "v":
        return Xy(pos.x, 1 if pos.y == height - 2 else pos.y + 1)
    elif direction == "<":
        return Xy(width - 2 if pos.x == 1 else pos.x - 1, pos.y)
    else:
        assert False, "What???"


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 299
    # Star 2: 899
