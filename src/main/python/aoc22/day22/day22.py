import logging
from typing import List

from util.data_io import read_input, read_test_input, timed_run
from util.log import log
from util.ds.grid import Grid
from util.ds.coord import UP, RIGHT, DOWN, LEFT

direction_costs = {
    RIGHT: 0,
    DOWN: 1,
    LEFT: 2,
    UP: 3,
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
            pass
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


def star2(lines: List[str]):
    """
    >>> star2(read_test_input(__file__))
    5031
    """

    pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 30552
    # Star 2:
