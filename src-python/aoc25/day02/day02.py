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
        result += _sum_invalid_ids(start, end, {2: [1], 4: [2], 6: [3], 8: [4], 10: [5]})
    return result


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    4174379265
    """
    result = 0
    for r in lines[0].split(","):
        start, end = map(int, r.split("-"))
        result += _sum_invalid_ids(start, end,
                                   {2: [1], 3: [1], 4: [2], 5: [1], 6: [2, 3], 7: [1], 8: [4], 9: [3], 10: [2, 5]})
    return result


# generate invalid IDs and check if in range
def _sum_invalid_ids(start, end, pattern_sizes) -> int:
    invalid_ids = set()
    total = 0

    for invalid_id_size in range(len(str(start)), len(str(end)) + 1):
        for pattern_size in pattern_sizes.get(invalid_id_size, []):
            pattern = 10 ** (pattern_size - 1)
            while True:
                invalid_id = int(str(pattern) * (invalid_id_size // pattern_size))
                if start <= invalid_id <= end and invalid_id not in invalid_ids:
                    log.debug(f"Invalid ID found: {invalid_id}")
                    invalid_ids.add(invalid_id)
                    total += invalid_id
                if invalid_id > end:
                    break
                pattern += 1
    return total


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=20223751480)
    timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=30260171216)
