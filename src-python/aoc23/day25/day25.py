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
    node_keys_copy = node_keys.copy()

    start_node = node_keys_copy.pop()
    # number of unique paths between all nodes
    #  key: total unique paths from start node to end node
    #  value: set of end nodes
    #  if there are only 3 unique paths, then the end_node must belong to the other group
    path_groups = {3: set(), 4: {start_node}}
    path_freq = defaultdict(int)  # optimization - to detect "cut-points", vertices which divide the groups
    most_frequent_vertices = None  # i.e. cut-points
    while node_keys_copy:
        end_node = node_keys_copy.pop()
        queue = [(start_node, [])]  # node, path
        visited: Set[Tuple[str, str]] = set()
        visited_all_paths: Set[Tuple[str, str]] = set()
        total_unique_paths = 0  # between start node and end node
        while queue:
            node, path = queue.pop(0)
            if node == end_node:
                log.debug(f"{start_node} -> {end_node}: {path}")
                visited_all_paths |= set(path)  # eliminate already used paths
                visited = set(visited_all_paths)
                # start new search with limited paths
                # use the last node from the same group, changing start node to quickly detect cut-points
                queue = [(list(path_groups[4])[-1], [])]
                total_unique_paths += 1
                if total_unique_paths > 3:
                    break  # if there are more than 3 unique paths, we're sure the end node belongs to the same group
                continue
            children = list(nodes[node])
            random.shuffle(children)  # random to detect cut-points
            for child in children:
                if (node, child) not in visited:
                    queue.append((child, path + [(node, child)]))
                    visited.add((node, child))
                    visited.add((child, node))
        path_groups[total_unique_paths] |= {end_node}
        if total_unique_paths == 3:  # i.e. the other group (start node and end node belongs to different groups)
            for vertex in visited_all_paths:
                path_freq[vertex] += 1
            most_frequent_vertices = {k: v for k, v in path_freq.items() if v == max(path_freq.values())}
            if len(most_frequent_vertices) == 3:  # cut-points detected
                log.debug(f"Bingo, cut-points found: {most_frequent_vertices}")
                break

    # optimization if we have 3 cut-points detected
    if len(most_frequent_vertices) == 3:
        # cut into 2 groups
        nodes_split = nodes.copy()
        for vertex in most_frequent_vertices:
            del nodes_split[vertex[0]]

        group1_count = 0
        queue = [start_node]
        visited = set()
        while queue:
            node = queue.pop(0)
            if node not in visited:
                visited.add(node)
                queue.extend(nodes_split.get(node, []))
                group1_count += 1
        group2_count = len(nodes) - group1_count
        return group1_count * group2_count
    else:
        return len(path_groups[3]) * len(path_groups[4])


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
