from typing import List

from data_input import read_all_lines


def star1(lines: List[str]):
    """
    >>> star1(["2-4,6-8",
    ...        "2-3,4-5",
    ...        "5-7,7-9",
    ...        "2-8,3-7",
    ...        "6-6,4-6",
    ...        "2-6,4-8",
    ...        ])
    2
    """

    total = 0
    for line in lines:
        el1, el2 = line.split(",")
        el1_lower, el1_upper = parse_pair(el1)
        el2_lower, el2_upper = parse_pair(el2)
        if ((el1_lower <= el2_lower and el1_upper >= el2_upper) or
                (el2_lower <= el1_lower and el2_upper >= el1_upper)):
            total += 1
    return total


def star2(lines: List[str]):
    """
    >>> star2(["2-4,6-8",
    ...        "2-3,4-5",
    ...        "5-7,7-9",
    ...        "2-8,3-7",
    ...        "6-6,4-6",
    ...        "2-6,4-8",
    ...        ])
    4
    """

    total = 0
    for line in lines:
        el1, el2 = line.split(",")
        el1_lower, el1_upper = parse_pair(el1)
        el2_lower, el2_upper = parse_pair(el2)
        if not ((el1_upper < el2_lower) or (el2_upper < el1_lower)):
            total += 1
    return total


def parse_pair(el1: str) -> List[int]:
    return [int(n) for n in el1.split("-")]


lines = read_all_lines("input.txt")
print(star1(lines))
print(star2(lines))

# Star 1: 569
# Star 2: 936
