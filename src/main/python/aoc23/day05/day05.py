import logging
import re
import sys

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    35
    """
    mappings = _parse_mappings(lines)
    seeds = _parse_seeds(lines)
    # create artificial ranges of length 1, to easily reuse star2 solution
    seed_ranges = [(seed, 1) for seed in seeds]
    return _solve(seed_ranges, mappings)


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    46
    """
    mappings = _parse_mappings(lines)
    seeds = _parse_seeds(lines)
    seed_ranges = [(seeds[i], seeds[i + 1]) for i in range(0, len(seeds) - 1, 2)]
    return _solve(seed_ranges, mappings)


def _parse_seeds(lines):
    return tuple(map(int, re.findall(r"(\d+)", lines[0])))


def _parse_mappings(lines):
    mappings = {}
    map_key = None
    for line in lines[2:]:
        if line:
            if "map" in line:
                map_key = line
                mappings[map_key] = []
            else:
                mappings[map_key].append(tuple(map(int, re.findall(r"(\d+)", line))))
    return mappings


def _solve(seed_ranges, mappings) -> int:
    def lookup_min_location(seed_range):
        log.debug(f"Looking up location for seed range {seed_range}")
        seed = seed_range[0]
        min_location = sys.maxsize
        while seed < seed_range[0] + seed_range[1]:
            log.debug(f"Checking seed {seed}")
            n = seed  # seed -> lookups -> location
            max_jump = sys.maxsize
            for map_name, ranges in mappings.items():
                log.debug(f"Looking up {n} for {map_name}")
                for dst_start, src_start, range_len in ranges:
                    src_end = src_start + range_len
                    if src_start <= n < src_end:
                        max_jump = min(max_jump, src_end - n)
                        n = dst_start + (n - src_start)
                        break
            log.debug(f"We can safely jump by {max_jump}")
            seed += max_jump
            min_location = min(min_location, n)
        return min_location

    return min(map(lookup_min_location, seed_ranges))


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 457535844
    # Star 2: 41222968
