import logging
import pprint
from collections import defaultdict
from typing import Dict, Set

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    54
    """
    nodes: Dict[str, Set[str]] = defaultdict(set)
    for line in lines:
        node, children = line.split(":")
        nodes[node].update(children.split())
        for child in children.split():
            nodes[child].add(node)
    log.debug(pprint.pformat(nodes))
    log.debug(len(nodes))


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))

    """
    for line in lines:
        pass


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1:
    # Star 2:
