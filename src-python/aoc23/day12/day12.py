import logging
import re
from typing import Dict, Tuple

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    21
    """
    return _solve(lines)


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    525152
    """
    return _solve(lines, pattern_multiplier=5)


def _solve(lines, pattern_multiplier=1):
    total = 0
    for line in lines:
        pattern, groups = line.split()
        log.debug(f"Pattern: {pattern} / {groups}")
        pattern = "?".join([pattern] * pattern_multiplier)
        groups = tuple(map(int, groups.split(","))) * pattern_multiplier
        total += _count_expanded_groups(groups, pattern, {})
    return total


def _count_expanded_groups(groups: Tuple, pattern: str, cache: Dict) -> int:
    """
    >>> _count_expanded_groups((1,), "??", {})
    2
    >>> _count_expanded_groups((1,), "#?", {})
    1
    >>> _count_expanded_groups((1,), "???", {})
    3
    >>> _count_expanded_groups((1, 1), "?????", {})
    6
    >>> _count_expanded_groups((1, 1), "#???#", {})
    1
    """
    if not groups:
        return 1
    group = groups[0]
    groups = groups[1:]
    total_size = len(pattern)
    group_size = group + 1 if groups else group  # last group doesn't need to end with .
    tail_size = sum(groups) + max(len(groups) - 1, 0)

    # speed optimization
    max_start = total_size - group_size - tail_size
    next_hash = pattern.find("#")
    if -1 < next_hash < max_start:
        max_start = min(max_start, next_hash)

    cache_key = (groups, pattern)
    if cache_key in cache:
        return cache[cache_key]

    solutions = 0
    for i in range(max_start + 1):
        solution = ("_" * i) + ("#" * group) + ("_" * (1 if groups else total_size - i - group))
        solution_pattern = pattern[:len(solution)]
        if re.match(_pattern_to_regex(solution_pattern), solution):  # check if the solution is correct
            tail_pattern = pattern[len(solution):]
            solutions += _count_expanded_groups(groups, tail_pattern, cache)

    cache[cache_key] = solutions

    return solutions


def _pattern_to_regex(pattern: str):
    return pattern.replace(".", "_").replace("?", ".")


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 7857
    # Star 2: 28606137449920
