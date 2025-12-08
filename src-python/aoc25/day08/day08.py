import dataclasses
import heapq
import logging
from functools import reduce

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xyz
from util.log import log


@dataclasses.dataclass(order=True, frozen=True)
class CoordDist:
    euclidean_dist: float
    coord1: Xyz
    coord2: Xyz


def star1(lines: list[str], limit: int):
    """
    >>> star1(read_test_input(__file__), limit=10)
    40
    """
    coords = [Xyz.parse(line) for line in lines]

    # 1) find shortest distances
    shortest_dists = _find_shortest_distances(coords, limit)

    # 2) create graph
    graph = {coord: [] for coord in coords}
    for dist in shortest_dists:
        graph[dist.coord1].append(dist.coord2)
        graph[dist.coord2].append(dist.coord1)

    # 3) find circuits
    circuits: list[set] = []
    nodes = coords.copy()
    while nodes:
        node = nodes.pop()
        circuit = {node}
        queue = {node}
        while queue:
            node = queue.pop()
            new_neighbors = [neighbor for neighbor in graph[node] if neighbor not in circuit]
            for new_neighbor in new_neighbors:
                circuit.add(new_neighbor)
                queue.add(new_neighbor)
                nodes.remove(new_neighbor)
        circuits.append(circuit)

    # 4) multiply 3 largest circuits
    return reduce(lambda a, b: a * b, sorted(map(len, circuits), reverse=True)[:3])


def star2(lines: list[str], limit: int | None = None):
    """
    >>> star2(read_test_input(__file__))
    25272
    """
    coords = [Xyz.parse(line) for line in lines]

    # 1) find shortest distances
    shortest_dists = _find_shortest_distances(coords, limit)

    # 2) keep building the graph and check if all connected
    def update_circuit(node: Xyz):
        queue = {node}
        while queue:
            node = queue.pop()
            if node not in circuit:
                circuit.add(node)
                queue.update(graph[node])

    graph = {coord: [] for coord in coords}
    circuit = {coords[0]}  # any circuit will do
    for dist in shortest_dists:
        coord1 = dist.coord1
        coord2 = dist.coord2
        graph[coord1].append(coord2)
        graph[coord2].append(coord1)

        if coord1 in circuit and coord2 not in circuit:
            update_circuit(coord2)

        if coord2 in circuit and coord1 not in circuit:
            update_circuit(coord1)

        if len(circuit) == len(coords):
            return coord1.x * coord2.x

    return "FAIL"


def _find_shortest_distances(coords: list[Xyz], limit: int | None) -> list[CoordDist]:
    # 1) find shortest distances
    shortest_dists: list[CoordDist] = []
    for i, coord1 in enumerate(coords[:-1]):
        for coord2 in coords[i + 1:]:
            coord_dist = CoordDist(-coord1.euclidean_dist(coord2), coord1, coord2)  # min heap therefore using -dist
            if not limit or len(shortest_dists) < limit:
                heapq.heappush(shortest_dists, coord_dist)
            elif coord_dist > shortest_dists[0]:
                heapq.heapreplace(shortest_dists, coord_dist)
    shortest_dists.sort(reverse=True)
    log.debug(shortest_dists)
    return shortest_dists


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__), limit=1000), expected_result=46398)
    timed_run("Star 2", lambda: star2(read_input(__file__), limit=10000), expected_result=8141888143)  # setting limit makes it faster
