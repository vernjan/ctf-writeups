import logging
from typing import List

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import UP, RIGHT, DOWN, LEFT, Xy
from util.ds.grid import Grid
from util.log import log

direction_costs = {
    RIGHT: 0,
    DOWN: 1,
    LEFT: 2,
    UP: 3,
}

N = UP
E = RIGHT
S = DOWN
W = LEFT

# TODO Maybe some general rules?
TRANSITIONS = {
    N: {
        N: lambda x, y, size: Xy(size - 1 - x, 0),  # 0
        E: lambda x, y, size: Xy(size - 1, size - 1 - x),  # 90
        S: lambda x, y, size: Xy(x, size - 1),  # 180
        W: lambda x, y, size: Xy(0, x),  # 270
    },
    E: {
        N: lambda x, y, size: Xy(size - 1 - y, 0),  # 270
        E: lambda x, y, size: Xy(size - 1, size - 1 - y),  # 0
        S: lambda x, y, size: Xy(y, size - 1),  # 90
        W: lambda x, y, size: Xy(0, y),  # 180
    },
    S: {
        N: lambda x, y, size: Xy(x, 0),  # 180
        E: lambda x, y, size: Xy(size - 1, x),  # 270
        S: lambda x, y, size: Xy(size - 1 - x, size - 1),  # 0
        W: lambda x, y, size: Xy(0, size - 1 - x),  # 90
    },
    W: {
        N: lambda x, y, size: Xy(y, 0),  # 90
        E: lambda x, y, size: Xy(size - 1, y),  # 180
        S: lambda x, y, size: Xy(size - 1 - y, size - 1),  # 270
        W: lambda x, y, size: Xy(0, size - 1 - y),  # 0
    }
}


def star1(lines: List[str]):
    """
    >>> star1(read_test_input(__file__))
    6032
    """

    instructions = _parse_instructions(lines[-1])
    grid = _parse_grid(lines[:-2])
    pos = grid.find_first(".")
    direction = RIGHT

    for instr in instructions:
        if isinstance(instr, int):
            steps = instr
            pos = grid.move(pos, steps, direction, stop_value="#", skip_value=" ", wrap_around=True, trace=True)
            log.debug(f"{instr}x {direction.value}")
            log.debug(grid)
        elif instr == "L":
            direction = direction.turn_left()
        elif instr == "R":
            direction = direction.turn_right()
        else:
            assert False, "What???"

    return (pos.y + 1) * 1000 + (pos.x + 1) * 4 + direction_costs[direction]


def _parse_instructions(path: str):
    instructions = []
    start = 0
    for i, char in enumerate(path):
        if str(char).isupper():
            instr_move = int("".join(path[start:i]))
            instr_turn = path[i:i + 1]
            instructions.extend([instr_move, instr_turn])
            start = i + 1
    instr_move = int("".join(path[start:]))
    instructions.append(instr_move)
    log.debug(instructions)
    return instructions


def _parse_grid(lines: List[str]):
    width = max(map(len, lines))
    rows = []
    for line in lines:
        row = line + (" " * (width - len(line)))
        rows.append(row)
    grid = Grid(rows)
    log.debug(grid)
    return grid


def star2(lines: List[str], grid_size):
    """
    >>> star2(read_test_input(__file__), 4)
    5031
    """

    cube_sides_mapping_test = {
        1: {
            N: (2, N),
            E: (6, E),
            S: (4, N),
            W: (3, N),
        },
        2: {
            N: (1, N),
            E: (3, W),
            S: (5, S),
            W: (6, S),
        },
        3: {
            N: (1, W),
            E: (4, W),
            S: (5, W),
            W: (2, E),
        },
        4: {
            N: (1, S),
            E: (6, N),
            S: (5, N),
            W: (3, S),
        },
        5: {
            N: (4, S),
            E: (6, W),
            S: (2, S),
            W: (3, S),
        },
        6: {
            N: (4, E),
            E: (1, E),
            S: (2, W),
            W: (5, E),
        },
    }

    cube_sides_mapping = {
        1: {
            N: (6, W),
            E: (2, W),
            S: (3, N),
            W: (4, W),
        },
        2: {
            N: (6, S),
            E: (5, E),
            S: (3, E),
            W: (1, E),
        },
        3: {
            N: (1, S),
            E: (2, S),
            S: (5, N),
            W: (4, N),
        },
        4: {
            N: (3, W),
            E: (5, W),
            S: (6, N),
            W: (1, W),
        },
        5: {
            N: (3, S),
            E: (2, E),
            S: (6, E),
            W: (4, E),
        },
        6: {
            N: (4, S),
            E: (5, S),
            S: (2, N),
            W: (1, N),
        },
    }

    instructions = _parse_instructions(lines[-1])
    cube_sides, master_grid = _parse_grids(lines[:-2], grid_size)

    grid_number = 1  # TODO name
    grid = cube_sides[grid_number]
    pos = grid.find_first(".")
    direction = RIGHT

    for instr in instructions:
        if isinstance(instr, int):
            steps = instr

            # TODO Can be removed I think
            next_grid_number = grid_number
            next_grid = grid
            next_pos = pos

            step_counter = 1
            while step_counter <= steps:
                grid.set_value(pos, direction.print_symbol)  # visual tracing
                next_pos = next_pos.neighbor(direction)

                next_grid_orientation = None
                if not grid.on_grid(next_pos):
                    # TODO next_grid_orientation invert already in mapping, but also in transitions ..?
                    next_grid_number, next_grid_orientation = cube_sides_mapping[grid_number][direction]
                    next_grid = cube_sides[next_grid_number]
                    next_pos = TRANSITIONS[direction][next_grid_orientation](pos.x, pos.y, grid_size)

                if next_grid.get_value(next_pos) == "#":
                    break

                grid_number = next_grid_number
                grid = next_grid
                if next_grid_orientation:
                    direction = next_grid_orientation.turn_right().turn_right()

                pos = next_pos
                step_counter += 1

            grid.set_value(pos, "x")

            log.info(f"{instr}x {direction.value}")
            # log.debug(_flatten_master_grid(master_grid, grid_size)) # TODO For tests only
        elif instr == "L":
            direction = direction.turn_left()
        elif instr == "R":
            direction = direction.turn_right()
        else:
            assert False, "What???"

    final_grid = _flatten_master_grid(master_grid, grid_size)
    final_pos = final_grid.find_first("x")

    return (final_pos.y + 1) * 1000 + (final_pos.x + 1) * 4 + direction_costs[direction]


def _parse_grids(lines, grid_size):
    width = max(map(len, lines))
    height = len(lines)

    rows = []
    for line in lines:
        row = line + (" " * (width - len(line)))
        rows.append(row)

    master_grid_rows = []
    cube_sides = {}
    for y in range(0, height, grid_size):
        master_grid_row = []
        for x in range(0, width, grid_size):
            value = rows[y][x]
            cube_side = Grid([line[x:x + grid_size] for line in rows[y:y + grid_size]])
            if value != " ":
                cube_sides[len(cube_sides) + 1] = cube_side
            master_grid_row.append(cube_side)
        master_grid_rows.append(master_grid_row)

    return cube_sides, Grid(master_grid_rows)  # TODO Move out cube_sides


def _flatten_master_grid(master_grid: Grid, grid_size) -> Grid:
    """Merge grid of grids into a single grid"""
    rows = []
    for y_master in range(master_grid.height):
        for y_inner in range(grid_size):
            merged_row = []
            for x_master in range(master_grid.width):
                inner_grid = master_grid.get(Xy(x_master, y_master))
                merged_row.extend(inner_grid.value.rows[y_inner])
            rows.append(merged_row)
    return Grid(rows)


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__), grid_size=50))

    # Star 1: 30552
    # Star 2:
