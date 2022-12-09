from typing import List

from data_input import read_all_lines
from simple_logging import log

GRID_SIZE_ROWS = 36
GRID_SIZE_COLS = 31
START_POS_X = 11
START_POS_Y = 17

# GRID_SIZE = 10000
# START_POS_X = 5000
# START_POS_Y = 5000


def star1(lines: List[str]):
    """
    >>> star1(read_all_lines("input-test.txt"))
    13
    """

    visited = set()
    head = (START_POS_X, START_POS_Y)
    tail = (START_POS_X, START_POS_Y)

    # Just for debugging
    # visual_grid = []
    # for _ in range(GRID_SIZE):
    #     row = ["." for _ in range(GRID_SIZE)]
    #     visual_grid.append(row)
    # _update_grid(visual_grid, head, head, tail, tail)
    # _print_grid(visual_grid)

    visited.add(tail)

    for line in lines:
        direction, steps = line.split(" ")
        # log.info(f"{direction} {steps}")

        for _ in range(int(steps)):
            head_old = head
            tail_old = tail

            head = _move_head(head, direction)
            tail = _tail_move(head, tail)
            visited.add(tail)

            # _update_grid(visual_grid, head, head_old, tail, tail_old)

        # _print_grid(visual_grid)

    return len(visited)


def _update_grid(grid, head, head_old, tail, tail_old):
    grid[head_old[1]][head_old[0]] = "."
    grid[tail_old[1]][tail_old[0]] = "#"
    grid[tail[1]][tail[0]] = "T"
    grid[head[1]][head[0]] = "H"




def _print_grid(grid):
    log.info("\n".join(["".join(cell) for cell in grid]))
    pass


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
    # straight moves
    if head[0] == tail[0] and abs(head[1] - tail[1]) == 2:
        return head[0], head[1] + (tail[1] - head[1]) // 2
    if head[1] == tail[1] and abs(head[0] - tail[0]) == 2:
        return head[0] + (tail[0] - head[0]) // 2, head[1]
    # diagonal moves
    if abs(head[0] - tail[0]) > 0 and abs(head[1] - tail[1]) == 2:
        return head[0], head[1] + (tail[1] - head[1]) // 2
    if abs(head[1] - tail[1]) > 0 and abs(head[0] - tail[0]) == 2:
        return head[0] + (tail[0] - head[0]) // 2, head[1]

    return tail


def star2(lines: List[str]):
    """
    >>> star2(read_all_lines("input-test2.txt"))
    36
    """

    rope = list([(START_POS_X, START_POS_Y) for _ in range(10)])

    visited = set()
    # head = (START_POS_X, START_POS_Y)
    # tail = (START_POS_X, START_POS_Y)

    visual_grid = []
    for _ in range(GRID_SIZE_ROWS):
        row = ["." for _ in range(GRID_SIZE_COLS)]
        visual_grid.append(row)
    _update_grid_rope(visual_grid, rope)
    _print_grid(visual_grid)

    visited.add((START_POS_X, START_POS_Y))

    for line in lines:
        direction, steps = line.split(" ")
        log.info(f"{direction} {steps}")


        for _ in range(int(steps)):
            rope[0] = _move_head(rope[0], direction)
            for i in range(0, len(rope) - 1):
                rope[i + 1] = _tail_move(rope[i], rope[i + 1])

            _update_grid_rope(visual_grid, rope)
            _print_grid(visual_grid)

            visited.add(rope[-1])





    return len(visited)

def _update_grid_rope(grid, rope):
    for i in range(GRID_SIZE_COLS):
        for j in range(GRID_SIZE_ROWS):
            grid[j][i] = "."
    for i in range(len(rope)):
        knot = rope[i]
        grid[knot[1]][knot[0]] = str(i)


if __name__ == "__main__":
    lines = read_all_lines("input.txt")
    print(f"Star 1: {star1(lines)}")
    print(f"Star 2: {star2(lines)}")

    # Star 1: 5874
    # Star 2:
