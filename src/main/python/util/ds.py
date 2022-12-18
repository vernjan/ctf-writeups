import re
from math import inf
from dataclasses import dataclass
from typing import List, Set, Sequence

from util.functions import array2d
from util.log import log


# TODO Tests
# TODO Typing
@dataclass(frozen=True)
class Xy:
    x: int
    y: int

    @staticmethod
    def parse(data: str):
        """
        >>> Xy.parse("2,3")
        (2,3)
        """
        coordinates = list(map(int, re.findall("[0-9]+", data)))
        assert len(coordinates) == 2, "2 numbers expected"
        return Xy(*coordinates)

    def __repr__(self) -> str:
        return f"({self.x},{self.y})"

    def up(self):
        return Xy(self.x, self.y - 1)

    def right(self):
        return Xy(self.x + 1, self.y)

    def down(self):
        return Xy(self.x, self.y + 1)

    def left(self):
        return Xy(self.x - 1, self.y)

    def left_down(self):
        return Xy(self.x - 1, self.y + 1)

    def right_down(self):
        return Xy(self.x + 1, self.y + 1)

    def neighbors(self, side=True, diagonal=False, min_x=-inf, max_x=inf, min_y=-inf, max_y=inf) -> List["Xy"]:
        """
        >>> Xy(0,1).neighbors()
        [(0,0), (1,1), (0,2), (-1,1)]
        >>> Xy(0,1).neighbors(min_x=0, max_x=2, min_y=0, max_y=2)
        [(0,0), (1,1), (0,2)]
        """
        neighbors = []
        if side:
            neighbors.extend([self.up(), self.right(), self.down(), self.left()])
        if diagonal:
            # TO-DO implement
            assert False, "Not yet implemented"

        return [xy for xy in neighbors if min_x <= xy.x <= max_x and min_y <= xy.y <= max_y]

    def manhattan_dist(self, other):
        """
        >>> Xy(1,1).manhattan_dist(Xy(2,2))
        2
        >>> Xy(4,5).manhattan_dist(Xy(0,0))
        9
        """
        return abs(self.y - other.y) + abs(self.x - other.x)


@dataclass(frozen=True)
class Xyz:
    x: int
    y: int
    z: int

    @staticmethod
    def parse(data: str):
        """
        >>> Xyz.parse("2,3,4")
        (2,3,4)
        """
        coordinates = list(map(int, re.findall("[0-9]+", data)))
        assert len(coordinates) == 3, "3 numbers expected"
        return Xyz(*coordinates)

    def __repr__(self) -> str:
        return f"({self.x},{self.y},{self.z})"

    def neighbors(self, side=True, edge=False, corner=False,
                  min_x=-inf, max_x=inf, min_y=-inf, max_y=inf, min_z=-inf, max_z=inf) -> List["Xyz"]:
        """
        >>> Xyz(0,1,2).neighbors()
        [(-1,1,2), (1,1,2), (0,0,2), (0,2,2), (0,1,1), (0,1,3)]
        >>> Xyz(0,1,2).neighbors(min_x=0, max_x=2, min_y=0, max_y=2, min_z=0, max_z=2)
        [(1,1,2), (0,0,2), (0,2,2), (0,1,1)]
        """
        neighbors = []
        if side:
            neighbors.extend([
                Xyz(self.x - 1, self.y, self.z),
                Xyz(self.x + 1, self.y, self.z),
                Xyz(self.x, self.y - 1, self.z),
                Xyz(self.x, self.y + 1, self.z),
                Xyz(self.x, self.y, self.z - 1),
                Xyz(self.x, self.y, self.z + 1),
            ])
        if edge:
            # TO-DO implement
            assert False, "Not yet implemented"
        if corner:
            # TO-DO implement
            assert False, "Not yet implemented"

        return [xyz for xyz in neighbors if
                min_x <= xyz.x <= max_x and min_y <= xyz.y <= max_y and min_z <= xyz.z <= max_z]


# TODO GridCell (no transposing, generics?)
class Grid:
    DIRECTIONS = ["NORTH", "EAST", "SOUTH", "WEST"]

    def __init__(self, rows: List[Sequence]):
        assert rows, "No data"

        self.rows = rows
        self.height = len(rows)
        self.width = len(rows[0])

        self.cols = []
        for ci in range(self.width):
            col = [rows[ri][ci] for ri in range(self.height)]
            self.cols.append(col)

        # TODO GridCell: Move away, keep memory in the GridCell
        self.visited = []
        for _ in range(self.height):
            self.visited.append([False] * self.width)

    @classmethod
    def empty(cls, width, height, value="."):
        """
        >>> print(Grid.empty(3, 2, "@"))
        @@@
        @@@
        """
        return Grid(array2d(width, height, value))

    def __getitem__(self, ri) -> List:
        return self.rows[ri]

    def __repr__(self) -> str:
        return "\n".join(["".join(map(str, row)) for row in self.rows])

    def fill_all(self, value):
        """
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).fill_all("@")
        @@@
        @@@
        @@@
        """
        self.rows = array2d(self.width, self.height, value)  # FIXME Does not init columns, visited, ..
        return self

    def fill_between(self, p1: Xy, p2: Xy, value):
        """
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).fill_between(Xy(0,1), Xy(2,1), "@")
        123
        @@@
        789
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).fill_between(Xy(2,1), Xy(0,1), "@")
        123
        @@@
        789
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).fill_between(Xy(1,0), Xy(1,2), "@")
        1@3
        4@6
        7@9
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).fill_between(Xy(1,2), Xy(1,0), "@")
        1@3
        4@6
        7@9
        """
        if p1.y == p2.y:
            p1_ci, p2_ci = (p1.x, p2.x) if p1.x < p2.x else (p2.x, p1.x)  # left to right, right to left
            for ri in range(p1_ci, p2_ci + 1):
                self[p1.y][ri] = value

        elif p1.x == p2.x:
            p1_ri, p2_ri = (p1.y, p2.y) if p1.y < p2.y else (p2.y, p1.y)
            for ri in range(p1_ri, p2_ri + 1):
                self[ri][p1.x] = value

        else:
            # TO-DO diagonal fill, ...
            assert False, "Not yet implemented"

        return self

    def find_first(self, value) -> Xy or None:
        """
        >>> Grid([[1,2],[2,3]]).find_first(2)
        (1,0)
        """
        for ri in range(self.height):
            for ci in range(self.width):
                if self[ri][ci] == value:
                    return Xy(ci, ri)
        return None

    def find_all(self, value) -> List[Xy]:
        """
        >>> Grid([[1,2],[2,3]]).find_all(2)
        [(1,0), (0,1)]
        """
        result = []
        for ri in range(self.height):
            for ci in range(self.width):
                if self[ri][ci] == value:
                    result.append(Xy(ci, ri))
        return result

    def at(self, pos: Xy):
        """
        >>> Grid([[1,2],[2,3]]).at(Xy(1,1))
        3
        """
        return self[pos.y][pos.x]

    def set(self, pos: Xy, value):
        """
        >>> Grid([[1,2],[2,3]]).set(Xy(1,1), "a")
        12
        2a
        """
        self[pos.y][pos.x] = value
        return self

    # TODO Add support for filling - slice_from, slice_between + fill_from, fill_between
    def slice_at(self, pos: Xy, direction) -> List:
        """Get a grid slice (list) from the given position moving into the given direction
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(Xy(1,1), "NORTH")
        [5, 2]
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(Xy(1,1), "EAST")
        [5, 6]
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(Xy(1,1), "SOUTH")
        [5, 8]
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(Xy(1,1), "WEST")
        [5, 4]
        """
        if direction == "NORTH":
            return self.cols[pos.x][pos.y::-1]
        elif direction == "EAST":
            return self.rows[pos.y][pos.x:]
        elif direction == "SOUTH":
            return self.cols[pos.x][pos.y:]
        elif direction == "WEST":
            return self.rows[pos.y][pos.x::-1]
        else:
            raise ValueError(f"Invalid direction: {direction}")

    # TODO Also add Rotate? Return new Grid for printing? Make sure to preserve Cells (to keep visited nodes)
    def view_from(self, direction):
        """Transpose the grid as if looked from the given direction"""
        if direction == "NORTH":
            return self.cols
        elif direction == "EAST":
            return [list(reversed(row)) for row in self.rows]
        elif direction == "SOUTH":
            return [list(reversed(row)) for row in self.cols]
        elif direction == "WEST":
            return self.rows
        else:
            raise ValueError(f"Invalid direction: {direction}")

    def get_neighbors(self, pos: Xy, side=True, diagonal=False) -> List["Xy"]:
        return pos.neighbors(side, diagonal, min_x=0, max_x=self.width - 1, min_y=0, max_y=self.height - 1)

    def is_visited(self, i, j, view_from="WEST"):
        ri, ci = self._transpose_coordinates(i, j, view_from)
        return self.visited[ri][ci]

    def mark_visited(self, i, j, view_from="WEST"):
        ri, ci = self._transpose_coordinates(i, j, view_from)
        self.visited[ri][ci] = True

    def _transpose_coordinates(self, ri, ci, view_from):
        if view_from == "NORTH":
            return ci, ri
        elif view_from == "EAST":
            return ri, len(self.cols[0]) - ci - 1
        elif view_from == "SOUTH":
            return len(self.cols[0]) - ci - 1, ri
        elif view_from == "WEST":
            return ri, ci
        else:
            raise ValueError(f"Invalid direction: {view_from}")

    def find_shortest_path(
            self,
            start_position: Xy,
            end_positions: Set[Xy],
            has_access) -> int:
        """ Find the shortest path between the start position and possibly multiple end positions.

        - has_access is a lambda(grid, position, neighbor_position)
        """
        shortest_routes = {start_position: 0}

        def _update_shortest_routes(pos, new_route_len):
            if pos not in shortest_routes:
                shortest_routes[pos] = new_route_len
                return True
            elif new_route_len < shortest_routes[pos]:
                shortest_routes[pos] = new_route_len
                return True
            return False

        next_moves = [start_position]
        while next_moves:
            position = next_moves.pop(0)

            if position in end_positions:
                log.debug(f"End position reached in: {shortest_routes[position]}")
                continue

            route_len = shortest_routes[position]
            for neighbor in self.get_neighbors(position):
                if has_access(self, position, neighbor):
                    if _update_shortest_routes(neighbor, route_len + 1):
                        next_moves.append(neighbor)

        return min([shortest_routes[pos] for pos in end_positions if pos in shortest_routes])
