import logging
import math

from util.data_io import read_input, read_test_input, timed_run
from util.ds.grid import LightGrid
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

    grid = LightGrid(lines)
    start_pos = (1, 0)
    exit_pos = (grid.width - 2, grid.height - 1)
    max_wait = math.lcm(grid.width - 2, grid.height - 2)  # blizzard positions are exactly the same after max_wait

    log.info("Pre-generating all blizzard states ..")
    blizzard_states = _generate_all_blizzard_states(grid, max_wait)

    return _go(start_pos, exit_pos, 0, max_wait, blizzard_states)


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    54
    """

    grid = LightGrid(lines)
    start_pos = (1, 0)
    exit_pos = (grid.width - 2, grid.height - 1)
    max_wait = math.lcm(grid.width - 2, grid.height - 2)  # blizzard positions are exactly the same after max_wait

    log.info("Pre-generating all blizzard states ..")
    blizzard_states = _generate_all_blizzard_states(grid, max_wait)

    trip1_time = _go(start_pos, exit_pos, 0, max_wait, blizzard_states)
    trip2_time = _go(exit_pos, start_pos, trip1_time, max_wait, blizzard_states)
    trip3_time = _go(start_pos, exit_pos, trip2_time, max_wait, blizzard_states)

    return trip3_time


def _go(start_pos, exit_pos, start_time, max_wait, blizzard_states: dict[int, LightGrid]):
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

        log.debug(time)
        log.debug(blizzard_states[time % max_wait])

        for delta_time in range(1, 10):  # safe choice is of course `max_wait + 1`
            grid = blizzard_states[(time + delta_time) % max_wait]

            for neighbor in grid.get_neighbors(pos):
                if grid.get(neighbor) == ".":
                    queue.append((neighbor, time + delta_time))

            if grid.get(pos) != ".":  # blizzard is here, we must move
                break
    return shortest_time


def _generate_all_blizzard_states(initial_grid: LightGrid, max_wait: int) -> dict[int, LightGrid]:
    blizzard_states = {}
    grid = initial_grid
    for time in range(max_wait):
        blizzard_states[time] = grid
        new_grid = LightGrid.empty(grid.width, grid.height)

        pos: tuple[int, int]
        for pos in grid.get_all_positions():
            cell_value = grid.get(pos)
            if cell_value == "#":
                new_grid.set(pos, "#")
            else:
                for value in cell_value:
                    if value == ".":
                        break
                    new_pos = _move_blizzard(pos[0], pos[1], value, grid.width, grid.height)
                    if new_grid.get(new_pos) == ".":
                        new_grid.set(new_pos, [])
                    new_grid.get(new_pos).append(value)

        grid = new_grid
    return blizzard_states


def _move_blizzard(x: int, y: int, direction: str, width: int, height: int) -> tuple[int, int]:
    if direction == "^":
        return x, height - 2 if y == 1 else y - 1
    elif direction == ">":
        return 1 if x == width - 2 else x + 1, y
    elif direction == "v":
        return x, 1 if y == height - 2 else y + 1
    elif direction == "<":
        return width - 2 if x == 1 else x - 1, y
    else:
        assert False, "What???"


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 299
    # Star 2: 899
