import itertools
import logging
import math
import re

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    6
    """
    return solve(lines, start_nodes_pattern="AAA", end_nodes_pattern="ZZZ")


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__, "input-test2.txt"))
    6
    """
    return solve(lines, start_nodes_pattern="A", end_nodes_pattern="Z")


def solve(lines, start_nodes_pattern: str, end_nodes_pattern):
    instructions = lines[0]
    nodes = {}
    next_node_names = []
    for line in lines[2:]:
        node_name, l, r = re.findall("[A-Z0-9]{3}", line)
        nodes[node_name] = (l, r)
        if node_name.endswith(start_nodes_pattern):
            next_node_names.append(node_name)

    log.debug(next_node_names)

    # The idea is to find a repeating cycle for each start node and then simply calculate the LCM of all cycles
    node_cycles = set()
    for next_node_name in next_node_names:
        log.debug(f"Finding end node for: {next_node_name}")

        steps_in_cycle = 0
        for inst in itertools.cycle(instructions):
            steps_in_cycle += 1
            node = nodes[next_node_name]
            next_node_name = node[0] if inst == "L" else node[1]
            if next_node_name.endswith(end_nodes_pattern):
                log.debug(f"End node {next_node_name} found in {steps_in_cycle} steps")
                node_cycles.add(steps_in_cycle)
                break

    return math.lcm(*node_cycles)


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 21409
    # Star 2: 21165830176709
