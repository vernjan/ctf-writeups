import logging
import re

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    8
    """
    limits = {"red": 12, "green": 13, "blue": 14}

    def check_game():
        for subset in subsets:
            for color_count in subset.split(","):
                count, color = color_count.split()
                if int(count) > limits[color]:
                    return False
        return True

    total = 0
    for line in lines:
        game_id = int(re.findall(r"Game (\d+):", line)[0])
        subsets = line.split(":")[1].split(";")
        if check_game():
            total += game_id

    return total


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    2286
    """

    def count_cubes_min():
        minimums = {"red": 0, "green": 0, "blue": 0}
        for subset in subsets:
            for color_count in subset.split(","):
                count, color = color_count.split()
                if int(count) > minimums[color]:
                    minimums[color] = int(count)
        return minimums

    total = 0
    for line in lines:
        subsets = line.split(":")[1].split(";")
        cubes_min = count_cubes_min()
        total += cubes_min["red"] * cubes_min["green"] * cubes_min["blue"]
    return total


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 2795
    # Star 2: 75561
