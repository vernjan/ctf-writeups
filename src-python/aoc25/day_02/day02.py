import logging

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    1227775554
    """
    result = 0
    for r in lines[0].split(","):
        start, end = map(int, r.split("-"))
        result += _sum_invalid_ids(start, end, len(str(end)) // 2)
    return result


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    4174379265
    """
    result = 0
    for r in lines[0].split(","):
        start, end = map(int, r.split("-"))
        for pattern_size in [2, 3, 4, 5]:
            result += _sum_invalid_ids(start, end, pattern_size)
    return result


def _sum_invalid_ids(start, end, pattern_size) -> int:
    # if pattern_size < 2:
    #     return 0

    start_str = str(start)

    # TODO JVe minus 1 patterns

    total = 0
    # pattern = int(start_str[0:pattern_size])

    for invalid_id_size in range(len(str(start)), len(str(end)) + 1):
        if invalid_id_size % pattern_size != 0 or pattern_size > invalid_id_size // 2:
            continue
        pattern = 10 ** (pattern_size - 1)
        while True:
            if len(set(str(pattern))) == 1:  # need extra handling for 1-size patterns
                pattern += 1
                continue

            invalid_id = int(str(pattern) * (invalid_id_size // pattern_size))
            # print(f"Checking invalid ID: {invalid_id}")
            if start <= invalid_id <= end:
                print(f"Invalid ID found: {invalid_id}")
                total += invalid_id
            if invalid_id > end:
                break
            pattern += 1
            # pattern %= 10 ** (pattern_size - 1)
    return total


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 20223751480
    # Star 2:
