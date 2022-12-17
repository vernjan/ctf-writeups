from dataclasses import dataclass
from typing import List, Tuple, Set, Sequence

from fce import array2d
from simple_logging import log


@dataclass
class Position:  # TODO x,y?
    ri: int  # row index
    ci: int  # column index

    @classmethod
    def parse(cls, data: str):
        """
        >>> Position.parse("5,8")
        (5,8)
        """
        ri = int(data.split(",")[0])
        ci = int(data.split(",")[1])
        return Position(ri, ci)

    @classmethod
    def parse_swap(cls, data: str): # TODO Go for standard X,Y?
        """
        >>> Position.parse_swap("5,8")
        (8,5)
        """
        ri = int(data.split(",")[1])
        ci = int(data.split(",")[0])
        return Position(ri, ci)

    def __repr__(self) -> str:
        return f"(ri={self.ri},ci={self.ci})"

    def __str__(self) -> str:
        return f"({self.ri},{self.ci})"

    def __hash__(self):
        return hash((self.ri, self.ci))

    def up(self):
        return Pos(self.ri - 1, self.ci)

    def right(self):
        return Pos(self.ri, self.ci + 1)

    def down(self):
        return Pos(self.ri + 1, self.ci)

    def left(self):
        return Pos(self.ri, self.ci - 1)

    def left_down(self):
        return Pos(self.ri + 1, self.ci - 1)

    def right_down(self):
        return Pos(self.ri + 1, self.ci + 1)

    def manhattan_dist(self, other):
        """
        >>> Position(1, 1).manhattan_dist(Position(2,2))
        2
        >>> Position(5, 4).manhattan_dist(Position(0,0))
        9
        """
        return abs(self.ri - other.ri) + abs(self.ci - other.ci)


Pos = Position


# TODO GridCell? No transposing? Generics?
# TODO Pos/Coord/Xy class, replace position, rowi/coli
class Grid:
    DIRECTIONS = ["NORTH", "EAST", "SOUTH", "WEST"]

    def __init__(self, rows: List[Sequence]):
        assert rows, "No data"

        self.rows = rows
        self.height = len(rows)
        self.width = len(rows[0])

        # TODO Do I need this???
        self.cols = []
        for ci in range(self.width):
            col = [rows[ri][ci] for ri in range(self.height)]
            self.cols.append(col)

        # TODO Move away?
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

    def fill_between(self, p1: Pos, p2: Pos, value):
        """
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).fill_between(Pos(1,0), Pos(1,2), "@")
        123
        @@@
        789
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).fill_between(Pos(1,2), Pos(1,0), "@")
        123
        @@@
        789
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).fill_between(Pos(0,1), Pos(2,1), "@")
        1@3
        4@6
        7@9
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).fill_between(Pos(2,1), Pos(0,1), "@")
        1@3
        4@6
        7@9
        """
        if p1.ri == p2.ri:
            p1_ci, p2_ci = (p1.ci, p2.ci) if p1.ci < p2.ci else (p2.ci, p1.ci)  # left to right, right to left
            for ri in range(p1_ci, p2_ci + 1):
                self[p1.ri][ri] = value

        elif p1.ci == p2.ci:
            p1_ri, p2_ri = (p1.ri, p2.ri) if p1.ri < p2.ri else (p2.ri, p1.ri)
            for ri in range(p1_ri, p2_ri + 1):
                self[ri][p1.ci] = value

        else:
            # TODO Diagonal fill, ...
            assert False, "Not supported"

        return self

    def find_first(self, value) -> Pos or None:
        """
        >>> Grid([[1,2],[2,3]]).find_first(2)
        (0,1)
        """
        for ri in range(self.height):
            for ci in range(self.width):
                if self[ri][ci] == value:
                    return Pos(ri, ci)
        return None

    def find_all(self, value) -> List[Pos]:
        """
        >>> Grid([[1,2],[2,3]]).find_all(2)
        [(0,1), (1,0)]
        """
        result = []
        for ri in range(self.height):
            for ci in range(self.width):
                if self[ri][ci] == value:
                    result.append(Pos(ri, ci))
        return result

    def at_position(self, pos: Pos):
        """
        >>> Grid([[1,2],[2,3]]).at_position(Pos(1,1))
        3
        """
        return self[pos.ri][pos.ci]

    def set_position(self, pos: Pos, value):
        """
        >>> Grid([[1,2],[2,3]]).set_position(Pos(1,1), "a")
        12
        2a
        """
        self[pos.ri][pos.ci] = value
        return self

    # TODO Add support for filling - slice_from, slice_between + fill_from, fill_between
    def slice_at(self, pos: Position, direction) -> List:
        """Get a grid slice (list) from the given position moving into the given direction
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(Pos(1, 1), "NORTH")
        [5, 2]
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(Pos(1, 1), "EAST")
        [5, 6]
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(Pos(1, 1), "SOUTH")
        [5, 8]
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(Pos(1, 1), "WEST")
        [5, 4]
        """
        if direction == "NORTH":
            return self.cols[pos.ci][pos.ri::-1]
        elif direction == "EAST":
            return self.rows[pos.ri][pos.ci:]
        elif direction == "SOUTH":
            return self.cols[pos.ci][pos.ri:]
        elif direction == "WEST":
            return self.rows[pos.ri][pos.ci::-1]
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

    # TODO Diagonal neighbors
    def get_neighbors(self, pos: Pos) -> List[Pos]:
        """
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).get_neighbors(Pos(0, 1))
        [(0,2), (1,1), (0,0)]
        """
        neighbors = [pos.up(), pos.right(), pos.down(), pos.left()]
        return [pos for pos in neighbors if 0 <= pos.ri < self.height and 0 <= pos.ci < self.width]

    def find_shortest_path(
            self,
            start_position: Pos,
            end_positions: Set[Pos],
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
