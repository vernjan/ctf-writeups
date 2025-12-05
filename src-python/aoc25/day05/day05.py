import dataclasses
import logging

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


# inclusive mutable range
@dataclasses.dataclass(order=True)
class Range:
    left: int
    right: int

    def __contains__(self, item):
        return self.left <= item <= self.right


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    3
    """
    ids, ranges = _parse_data(lines)

    result = 0
    for id in ids:
        for r in ranges:
            if id in r:
                result += 1
                break
    return result


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    14
    """
    _, ranges = _parse_data(lines)

    merged_ranges: list[Range] = []
    for r in sorted(ranges):
        for mr in merged_ranges:
            if r.left in mr:
                r.left = mr.right + 1
            if r.right in mr:
                r.right = mr.left - 1
        if r.left <= r.right:
            merged_ranges.append(r)

    log.debug(merged_ranges)

    result = 0
    for mr in merged_ranges:
        result += mr.right - mr.left + 1
    return result


def _parse_data(lines) -> tuple[list[int], list[Range]]:
    ranges = []
    ids = []
    for line in lines:
        if "-" in line:
            start, end = map(int, line.split("-"))
            ranges.append(Range(start, end))
        elif line:
            ids.append(int(line))
    return ids, ranges


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=811)
    timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=338189277144473)
