import logging
import re
from typing import List

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    21
    """
    total = 0
    for line in lines:
        pattern, groups = line.split()
        total_space = len(pattern)
        groups = list(map(int, groups.split(",")))
        solutions = _generate_groups(groups, total_space, pattern)
        for solution in solutions:
            if re.match(_pattern_to_regex(pattern), solution):
                log.debug(f"Matching {pattern} against {solution} -> OK")
                total += 1
            else:
                log.debug(f"Matching {pattern} against {solution} -> FAIL")

    return total


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))

    """


def _pattern_to_regex(pattern: str):
    return pattern.replace(".", "_").replace("?", ".")


def _generate_groups(groups: List[int], total_space: int, pattern: str = None):
    """
    >>> _generate_groups([1], 2, "??")
    ['#_', '_#']
    >>> _generate_groups([1], 2, "#?")
    ['#_']
    >>> _generate_groups([1], 3, "???")
    ['#__', '_#_', '__#']
    >>> _generate_groups([5], 5, "??#??")
    ['#####']
    >>> _generate_groups([1, 1], 3, "??#")
    ['#_#']
    >>> _generate_groups([2, 1], 5, "?????")
    ['##_#_', '##__#', '_##_#']
    >>> _generate_groups([1, 1], 5, "?????")
    ['#_#__', '#__#_', '#___#', '_#_#_', '_#__#', '__#_#']
    >>> _generate_groups([1, 1], 5, "#???#")
    ['#___#']
    """
    if not groups:
        return [""]
    group = groups[0]
    groups = groups[1:]
    group_size = group + 1 if groups else group  # last group doesn't need to end with .
    tail_size = sum(groups) + max(len(groups) - 1, 0)
    max_start = total_space - group_size - tail_size
    solutions = list()
    for i in range(max_start + 1):
        solution = ("_" * i) + ("#" * group) + ("_" * (1 if groups else total_space - i - group))
        if re.match(_pattern_to_regex(pattern[:len(solution)]), solution):
            for rec_solution in _generate_groups(groups, total_space - len(solution), pattern[len(solution):]):
                solutions.append(solution + "".join(rec_solution))
    return solutions


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 7857
    # Star 2:
