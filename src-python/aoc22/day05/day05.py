import re
from typing import List

from util.data_io import read_input, read_test_input


def star1(lines: List[str]):
    """
    >>> star1(read_test_input(__file__))
    'CMZ'
    """

    return _move_creates(lines, "star1")


def star2(lines: List[str]):
    """
    >>> star2(read_test_input(__file__))
    'MCD'
    """

    return _move_creates(lines, "star2")


def _move_creates(lines: List[str], star: str) -> str:
    stacks = []
    for line in lines:
        # Init stacks
        if "[" in line:
            for i in range(1, len(line), 4):
                if line[i].isupper():
                    stack_index = i // 4
                    while stack_index >= len(stacks):
                        stacks.append([])
                    stacks[stack_index].insert(0, line[i])

        # Do moves
        if "move" in line:
            number, _from, to = [int(n) for n in re.findall("[0-9]+", line)]
            if star == "star1":
                for _ in range(number):
                    pop = stacks[_from - 1].pop()
                    stacks[to - 1].append(pop)
            if star == "star2":
                batch = []
                for _ in range(number):
                    pop = stacks[_from - 1].pop()
                    batch.insert(0, pop)
                stacks[to - 1].extend(batch)

    return "".join(stack[-1] for stack in stacks)


if __name__ == "__main__":
    print(star1(read_input(__file__)))
    print(star2(read_input(__file__)))

    # Star 1: QNHWJVJZW
    # Star 2: BPCZJLFJW
