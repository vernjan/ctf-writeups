import logging
from typing import List

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import UP as N, RIGHT as E, DOWN as S, LEFT as W
from util.ds.cube2d import SURFACE_TRANSITIONS, parse_2dcube, merge_cube2d, get_cube_sides
from util.ds.grid import Grid
from util.log import log
from data import CUBE, CUBE_TEST

DIRECTION_COSTS = {E: 0, S: 1, W: 2, N: 3}


def star1(lines: List[str]):
    """
    >>> star1(read_test_input(__file__))
    6032
    """

    instructions = _parse_instructions(lines[-1])
    grid = _parse_grid(lines[:-2])
    pos = grid.find_first(".")
    direction = E

    for instr in instructions:
        if isinstance(instr, int):
            steps = instr
            pos = grid.walk(pos, steps, direction, stop_value="#", skip_value=" ", wrap_around=True, trace=True)
            log.debug(f"{instr}x {direction.value}")
            log.debug(grid)
        elif instr == "L":
            direction = direction.turn_left()
        elif instr == "R":
            direction = direction.turn_right()
        else:
            assert False, "What???"

    return (pos.y + 1) * 1000 + (pos.x + 1) * 4 + DIRECTION_COSTS[direction]


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


def star2(lines: List[str], cube_sides_mapping, cube_size):
    """
    >>> star2(read_test_input(__file__), CUBE_TEST, 4)
    5031
    """

    instructions = _parse_instructions(lines[-1])
    cube2d = parse_2dcube(lines[:-2], cube_size)
    cube_sides = get_cube_sides(cube2d)
    cube_side_number = 1
    cube_side = cube_sides[cube_side_number]
    pos = cube_side.find_first(".")
    direction = E

    for instr in instructions:
        if isinstance(instr, int):
            steps = instr
            step_counter = 1
            while step_counter <= steps:
                cube_side.set_value(pos, direction.print_symbol)  # visual tracing

                next_pos = pos.neighbor(direction)

                if not cube_side.has(next_pos):
                    next_cube_side_number, next_grid_orientation = cube_sides_mapping[cube_side_number][direction]
                    next_cube_side = cube_sides[next_cube_side_number]
                    next_pos = SURFACE_TRANSITIONS[direction][next_grid_orientation](pos.x, pos.y, cube_size)

                    if next_cube_side.get_value(next_pos) == "#":
                        break

                    cube_side_number = next_cube_side_number
                    cube_side = next_cube_side
                    direction = next_grid_orientation.turn_around()

                elif cube_side.get_value(next_pos) == "#":
                    break

                pos = next_pos
                step_counter += 1

            cube_side.set_value(pos, "x")

            if __name__ != "__main__":
                log.debug(f"{instr}x {direction.value}")
                log.debug(merge_cube2d(cube2d, cube_size))
        elif instr == "L":
            direction = direction.turn_left()
        elif instr == "R":
            direction = direction.turn_right()
        else:
            assert False, "What???"

    cube2d_flat = merge_cube2d(cube2d, cube_size)
    pos = cube2d_flat.find_first("x")

    return (pos.y + 1) * 1000 + (pos.x + 1) * 4 + DIRECTION_COSTS[direction]


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__), CUBE, cube_size=50))

    # Star 1: 30552
    # Star 2: 184106
