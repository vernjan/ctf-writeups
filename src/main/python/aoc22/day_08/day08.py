from typing import List
from simple_logging import log

from data_input import read_all_lines


def star1(lines: List[str]):
    """
    >>> star1(read_all_lines("input-test.txt"))
    'TODO'
    """

    pass


def star2(lines: List[str]):
    """
    >>> star2(read_all_lines("input-test.txt"))
    'TODO'
    """

    pass


if __name__ == "__main__":
    lines = read_all_lines("input.txt")
    print(f"Star 1: {star1(lines)}")
    print(f"Star 2: {star2(lines)}")

    # Star 1:
    # Star 2:
