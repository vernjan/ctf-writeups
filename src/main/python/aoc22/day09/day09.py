import logging
from typing import List

from util.data_io import read_input, read_test_input, read_file
from util.log import log
from util.ds import Grid
from util.functions import signum

with_visual_grid = __name__ != "__main__"  # Only for tests


def _move_head(head, direction):
    if direction == "U":
        return head[0], head[1] - 1
    if direction == "R":
        return head[0] + 1, head[1]
    if direction == "D":
        return head[0], head[1] + 1
    if direction == "L":
        return head[0] - 1, head[1]
    else:
        assert False, "Shouldn't happen"


def _tail_move(head, tail):
    hx = head[0]
    tx = tail[0]
    hy = head[1]
    ty = tail[1]

    if abs(hx - tx) > 1 or abs(hy - ty) > 1:
        return tx + signum(hx - tx), ty + signum(hy - ty)

    return tail


def star1(commands: List[str]):
    """
    >>> star1(read_test_input(__file__))
    13
    """

    visited = set()
    head = (5000, 5000)
    tail = (5000, 5000)

    grid = Grid.empty(width=6, height=5)

    if with_visual_grid:
        head = (0, 4)
        tail = (0, 4)
        log.debug("Initial state:")
        _update_visual_grid(grid, head, tail)

    visited.add(tail)

    for cmd in commands:
        direction, steps = cmd.split(" ")
        log.debug(f"{direction} {steps}:")

        for _ in range(int(steps)):
            head = _move_head(head, direction)
            tail = _tail_move(head, tail)
            visited.add(tail)

        if with_visual_grid:
            _update_visual_grid(grid, head, tail)

    return len(visited)


def _update_visual_grid(grid, head, tail):
    grid.fill_all(".")
    grid.rows[tail[1]][tail[0]] = "T"
    grid.rows[head[1]][head[0]] = "H"
    log.info(grid)


def star2(commands: List[str]):
    """
    >>> star2(read_file(__file__, "input-test2.txt"))
    36
    """

    visited = set()
    rope = [(5000, 5000)] * 10

    grid = Grid.empty(width=25, height=25)

    if with_visual_grid:
        rope = [(10, 10)] * 10
        _update_visual_grid_with_rope(grid, rope)

    visited.add(rope[-1])

    for cmd in commands:
        direction, steps = cmd.split(" ")
        log.debug(f"{direction} {steps}")

        for _ in range(int(steps)):
            rope[0] = _move_head(rope[0], direction)
            for i in range(0, len(rope) - 1):
                rope[i + 1] = _tail_move(rope[i], rope[i + 1])

            visited.add(rope[-1])

        if with_visual_grid:
            _update_visual_grid_with_rope(grid, rope)

    return len(visited)


def _update_visual_grid_with_rope(grid, rope):
    grid.fill_all(".")
    for i in range(len(rope)):
        knot = rope[i]
        grid.rows[knot[1]][knot[0]] = str(i)
    log.info(grid)


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    lines = read_input(__file__)
    print(f"Star 1: {star1(lines)}")
    print(f"Star 2: {star2(lines)}")

    # Star 1: 5874
    # Star 2: 2467
