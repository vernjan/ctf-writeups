import re
from typing import List

from data_input import read_all_lines


def star1(lines: List[str]):
    """
    >>> star1(["    [D]",
    ...        "[N] [C]",
    ...        "[Z] [M] [P]",
    ...        " 1   2   3 ",
    ...        "",
    ...        "move 1 from 2 to 1",
    ...        "move 3 from 1 to 3",
    ...        "move 2 from 2 to 1",
    ...        "move 1 from 1 to 2",
    ...        ])
    'CMZ'
    """

    answer = ""
    stacks = []
    for line in lines:
        # Init stacks
        if "[" in line:
            for i in range(1, len(line), 4):
                letter = line[i]
                if letter.isupper():
                    stack_index = i // 4
                    while stack_index >= len(stacks):
                        stacks.append([])
                    stacks[stack_index].insert(0, letter)

        # Do moves
        if "move" in line:
            number, _from, to = [int(n) for n in re.findall("[0-9]+", line)]
            for _ in range(number):
                pop = stacks[_from - 1].pop()
                stacks[to - 1].append(pop)

    for stack in stacks:
        answer += stack[-1]

    return answer


def star2(lines: List[str]):
    """
    >>> star2(["    [D]",
    ...        "[N] [C]",
    ...        "[Z] [M] [P]",
    ...        " 1   2   3 ",
    ...        "",
    ...        "move 1 from 2 to 1",
    ...        "move 3 from 1 to 3",
    ...        "move 2 from 2 to 1",
    ...        "move 1 from 1 to 2",
    ...        ])
    'MCD'
    """

    answer = ""
    stacks = []
    for line in lines:
        # Init stacks
        if "[" in line:
            for i in range(1, len(line), 4):
                letter = line[i]
                if letter.isupper():
                    stack_index = i // 4
                    while stack_index >= len(stacks):
                        stacks.append([])
                    stacks[stack_index].insert(0, letter)

        # Do moves
        if "move" in line:
            number, _from, to = [int(n) for n in re.findall("[0-9]+", line)]
            batch = []
            for _ in range(number):
                batch.insert(0, stacks[_from - 1].pop())
            stacks[to - 1].extend(batch)

    for stack in stacks:
        answer += stack[-1]

    return answer


if __name__ == "__main__":
    lines = read_all_lines("input.txt")
    print(star1(lines))
    print(star2(lines))

    # Star 1: QNHWJVJZW
    # Star 2: BPCZJLFJW
