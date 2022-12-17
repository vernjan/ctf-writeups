import logging
from typing import List
from simple_logging import log

from data_input import read_all_lines
from ds import Grid


def star1(jets: str, rocks_count: int):
    """
    >>> star1(read_all_lines("input-test.txt")[0], 20)
    3068
    """

    grid = Grid.empty(width=7, height=25, value=".")
    jet_index = 0

    for rock_index in range(rocks_count):
        rock = rock_index % 5
        jet = jets[jet_index]
        log.debug(f"Rock: {rock}, jet: {jet}")

        log.debug(grid)

        jet_index = (jet_index + 1) % len(jets)



def star2(jets: str, rocks_count: int):
    """
    >>> star2(read_all_lines("input-test.txt"))
    'TODO'
    """

    pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    jets = read_all_lines("input.txt")[0]
    print(f"Star 1: {star1(jets), 2022}")
    print(f"Star 2: {star2(jets), 2022}")

    # Star 1:
    # Star 2:
