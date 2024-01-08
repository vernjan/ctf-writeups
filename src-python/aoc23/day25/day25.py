import logging
import random
from collections import defaultdict
from typing import Dict, Set, Tuple

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    54
    """
    nodes = _parse_nodes(lines)
    node_keys = list(nodes.keys())
    random.shuffle(node_keys)  # just for fun

    start_node = node_keys[0]
    # number of unique paths between all nodes, if there are only 3 unique paths,
    # then the end_node belongs to the second group
    path_groups = {3: 0, 4: 1}  # 1 for the start node
    for end_node in node_keys[1:]:
        queue = [(start_node, [])]
        visited: Set[Tuple[str, str]] = set()
        visited_all_paths: Set[Tuple[str, str]] = set()
        total_unique_paths = 0
        while queue:
            node, path = queue.pop(0)
            if node == end_node:
                log.debug(f"{start_node} -> {end_node}: {path}")
                visited_all_paths |= set(path)  # eliminate already used paths
                visited = set(visited_all_paths)
                queue = [(start_node, [])]  # start new search with limited paths
                total_unique_paths += 1
                if total_unique_paths > 3:
                    break
                continue
            for child in nodes[node]:
                if (node, child) not in visited:
                    queue.append((child, path + [(node, child)]))
                    visited.add((node, child))
                    visited.add((child, node))
        path_groups[total_unique_paths] += 1

    log.debug(path_groups)
    return path_groups[3] * path_groups[4]


def _parse_nodes(lines):
    nodes: Dict[str, Set[str]] = defaultdict(set)
    for line in lines:
        node, children = line.split(":")
        nodes[node].update(children.split())
        for child in children.split():
            nodes[child].add(node)
    return nodes


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))

    # Star 1: 551196
