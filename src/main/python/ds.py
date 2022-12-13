from typing import List, Tuple, Set, Sequence

from fce import array2d
from simple_logging import log


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
        self._cols = []
        for coli in range(self.width):
            col = [rows[rowi][coli] for rowi in range(self.height)]
            self._cols.append(col)

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

    def __getitem__(self, rowi) -> List:
        return self.rows[rowi]

    def __repr__(self) -> str:
        return "\n".join(["".join(row) for row in self.rows])

    def fill(self, symbol="."):
        self.rows = array2d(self.width, self.height, symbol)  # FIXME Does not init columns, visited, ..

    def find_first(self, value):
        """
        >>> Grid([[1,2],[2,3]]).find_first(2)
        (0, 1)
        """
        for rowi in range(self.height):
            for coli in range(self.width):
                if self[rowi][coli] == value:
                    return rowi, coli
        return None

    def find_all(self, value) -> List:
        """
        >>> Grid([[1,2],[2,3]]).find_all(2)
        [(0, 1), (1, 0)]
        """
        result = []
        for rowi in range(self.height):
            for coli in range(self.width):
                if self[rowi][coli] == value:
                    result.append((rowi, coli))
        return result

    def at_position(self, position: Tuple[int, int]):
        """
        >>> Grid([[1,2],[2,3]]).at_position((1,1))
        3
        """
        return self[position[0]][position[1]]

    def slice_at(self, rowi, coli, direction) -> List:
        """Get a grid slice (list) from the given position moving into the given direction
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(1, 1, "NORTH")
        [5, 2]
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(1, 1, "EAST")
        [5, 6]
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(1, 1, "SOUTH")
        [5, 8]
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(1, 1, "WEST")
        [5, 4]
        """
        if direction == "NORTH":
            return self._cols[coli][rowi::-1]
        elif direction == "EAST":
            return self.rows[rowi][coli:]
        elif direction == "SOUTH":
            return self._cols[coli][rowi:]
        elif direction == "WEST":
            return self.rows[rowi][coli::-1]
        else:
            raise ValueError(f"Invalid direction: {direction}")

    # TODO Also add Rotate? Return new Grid for printing? Make sure to preserve Cells (to keep visited nodes)
    def view_from(self, direction):
        """Transpose the grid as if looked from the given direction"""
        if direction == "NORTH":
            return self._cols
        elif direction == "EAST":
            return [list(reversed(row)) for row in self.rows]
        elif direction == "SOUTH":
            return [list(reversed(row)) for row in self._cols]
        elif direction == "WEST":
            return self.rows
        else:
            raise ValueError(f"Invalid direction: {direction}")

    def is_visited(self, i, j, view_from="WEST"):
        rowi, coli = self._transpose_coordinates(i, j, view_from)
        return self.visited[rowi][coli]

    def mark_visited(self, i, j, view_from="WEST"):
        rowi, coli = self._transpose_coordinates(i, j, view_from)
        self.visited[rowi][coli] = True

    def _transpose_coordinates(self, rowi, coli, view_from):
        if view_from == "NORTH":
            return coli, rowi
        elif view_from == "EAST":
            return rowi, len(self._cols[0]) - coli - 1
        elif view_from == "SOUTH":
            return len(self._cols[0]) - coli - 1, rowi
        elif view_from == "WEST":
            return rowi, coli
        else:
            raise ValueError(f"Invalid direction: {view_from}")

    def get_neighbors(self, pos: Tuple[int, int]) -> List[Tuple[int, int]]:
        """
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).get_neighbors((0, 1))
        [(0, 2), (1, 1), (0, 0)]
        """
        neighbors = [
            (pos[0] - 1, pos[1]),
            (pos[0], pos[1] + 1),
            (pos[0] + 1, pos[1]),
            (pos[0], pos[1] - 1),
        ]

        return [pos for pos in neighbors if 0 <= pos[0] < self.height and 0 <= pos[1] < self.width]

    def find_shortest_path(
            self,
            start_position: Tuple[int, int],
            end_positions: Set[Tuple[int, int]],
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
