import logging
from collections import defaultdict

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    5
    """
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

    # mark visited nodes - node all nodes are on the path
    visited: set[str] = set()
    queue = {"you"}
    while queue:
        node = queue.pop()
        visited.add(node)
        if node != "out":
            queue.update(graph[node])
    log.debug(visited)

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


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    2
    """
    for line in lines:
        pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=None)
    timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=None)
