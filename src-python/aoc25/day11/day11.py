import logging
from collections import defaultdict
from dataclasses import dataclass
from functools import reduce

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    5
    """
    graph_inverted, visited = _setup_graph_info(lines, "you")

    def sum_parent_nodes(node: str) -> int:
        if node not in visited:
            return 0
        if node == "you":
            return 1

        total = 0
        for parent in graph_inverted[node]:
            total += sum_parent_nodes(parent)
        return total

    return sum_parent_nodes("out")


@dataclass
class NodeInfo:
    path_count: int  # path count (no filters)
    path_count_filter1: int  # path count filtered by dac or fft
    path_count_filter2: int  # path count filtered by both dac and fft

    def __add__(self, other):
        return NodeInfo(
            self.path_count + other.path_count,
            self.path_count_filter1 + other.path_count_filter1,
            self.path_count_filter2 + other.path_count_filter2
        )


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__, input_file="input-test-s2.txt"))
    2
    """
    graph_inverted, visited = _setup_graph_info(lines, "svr")

    cache: dict[str, NodeInfo] = {}  # memoization is a must-have but complicates filtering by visited nodes

    def sum_parent_nodes(node: str) -> NodeInfo:
        if node in cache:
            return cache[node]

        if node not in visited:
            return NodeInfo(0, 0, 0)

        if node == "svr":
            return NodeInfo(1, 0, 0)

        node_info = reduce(lambda node, parent: node + parent, map(sum_parent_nodes, graph_inverted[node]))

        if node in ["dac", "fft"]:
            if not node_info.path_count_filter1:
                node_info.path_count_filter1 = node_info.path_count
            else:
                node_info.path_count_filter2 = node_info.path_count_filter1

        cache[node] = node_info
        return node_info

    return sum_parent_nodes("out").path_count_filter2


def _setup_graph_info(lines: list[str], start_node):
    graph: dict[str, set[str]] = {}
    for line in lines:
        node, children_str = line.split(": ")
        children = children_str.split(" ")
        graph[node] = set(children)
    log.debug(graph)

    graph_inverted: dict[str, set[str]] = defaultdict(set)
    for node, children in graph.items():
        for child in children:
            graph_inverted[child].add(node)
    log.debug(graph_inverted)

    # mark visited nodes - not all nodes are on the path
    visited: set[str] = set()
    queue = {start_node}
    while queue:
        node = queue.pop()
        visited.add(node)
        if node != "out":
            queue.update(graph[node])
    log.debug(visited)

    return graph_inverted, visited


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=746)
    timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=370500293582760)
