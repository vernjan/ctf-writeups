import pprint
import re
import logging

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    35
    """

    def lookup_location(seed):
        return seed

    def lookup(val):
        # Kid wakes up ..
        pass

    seeds = re.findall(r"(\d+)", lines[0])
    maps = {}
    map_key = None
    log.debug(f"Seeds: {seeds}")
    for line in lines[2:]:
        if not line:
            continue

        log.debug(f"Line: {line}")
        if "map" in line:
            map_key = line
            maps[map_key] = {}
            continue

        dst_start, src_start, range_len = map(int, re.findall(r"(\d+)", line))
        maps[map_key][(src_start, range_len)] = dst_start

    log.debug(pprint.pformat(maps))
    return min(map(lookup_location, seeds))


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))

    """
    for line in lines:
        pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1:
    # Star 2:
