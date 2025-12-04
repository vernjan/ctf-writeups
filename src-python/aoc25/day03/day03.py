import logging

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    357
    """
    return _count_joltage(lines, 2)


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    3121910778619
    """
    return _count_joltage(lines, 12)


def _count_joltage(lines: list[str], num_of_batteries: int) -> int:
    total_joltage = 0
    for battery in lines:
        battery_indexes = list(range(num_of_batteries))
        for i, bi in enumerate(battery_indexes):
            for j in range(bi + 1, len(battery) - (num_of_batteries - 1 - i)):
                if int(battery[j]) > int(battery[battery_indexes[i]]):
                    battery_indexes[i] = j
                    # reset all remaining indexes
                    c = 1
                    for k in range(i + 1, num_of_batteries):
                        battery_indexes[k] = j + c
                        c += 1

        joltage = int("".join(map(lambda i: battery[i], battery_indexes)))
        log.debug(f"Joltage: {joltage}")
        total_joltage += joltage

    return total_joltage


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=17095)
    timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=168794698570517)
