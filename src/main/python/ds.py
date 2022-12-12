from typing import Iterable, List, Tuple, Set

from simple_logging import log


# TODO Pos/Coord/Xy class
# TODO Typing for all
# TODO Docs
# TODO GridCell? No transposing?
class Grid:
    class Cell:
        def __int__(self, rowi, coli, val):
            self.rowi = rowi
            self.coli = coli
            self.val = val
            self.visited = False

    DIRECTIONS = ["UP", "RIGHT", "DOWN", "LEFT"]  # TODO vs. Views?

    # TODO Clean up
    def __init__(self, data: List[str]):
        self.rows = []
        self.cols = []

        # for rowi in range(len(data)):

        # FIXME !!! str vs int
        for row in data:
            # self.rows.append([int(item) for item in row])
            self.rows.append([item for item in row])

        # TODO row_size and col_size
        for coli in range(len(data[0])):
            col = []
            for row_index in range(len(data)):
                # col.append(int(data[row_index][coli]))
                col.append(data[row_index][coli])
            self.cols.append(col)

        # TODO More Pythonic way?
        self.visited = []
        for _ in range(self.cols_count()):
            row = [False for _ in range(self.rows_count())]
            self.visited.append(row)

    def __getitem__(self, item):
        return self.rows[item]

    # TODO find_all, better impl?
    def find_first(self, value):
        for i in range(len(self.rows)):
            row = self.rows[i]
            for j in range(len(row)):
                if row[j] == value:
                    return i, j
        return None

    def find_all(self, value):
        result = []
        for i in range(len(self.rows)):
            row = self.rows[i]
            for j in range(len(row)):
                if row[j] == value:
                    result.append((i, j))
        return result

    def at_pos(self, pos: Tuple[int, int]):
        return self[pos[0]][pos[1]]

    def rows_count(self) -> int:
        return len(self.rows)

    def cols_count(self) -> int:
        return len(self.cols)

    def slice_from(self, rowi, coli, direction) -> Iterable:
        """Get a grid slice from the given position moving into the given direction"""
        if direction == "UP":
            return self.cols[coli][rowi::-1]
        elif direction == "RIGHT":
            return self.rows[rowi][coli:]
        elif direction == "DOWN":
            return self.cols[coli][rowi:]
        elif direction == "LEFT":
            return self.rows[rowi][coli::-1]
        else:
            raise ValueError(f"Invalid direction: {direction}")

    # TODO Rotate?
    def view_from(self, direction):
        """Transpose the grid as if looked from the given direction"""
        if direction == "UP":
            return self.cols
        elif direction == "RIGHT":
            return [list(reversed(row)) for row in self.rows]
        elif direction == "DOWN":
            return [list(reversed(row)) for row in self.cols]
        elif direction == "LEFT":
            return self.rows
        else:
            raise ValueError(f"Invalid direction: {direction}")

    def is_visited(self, i, j, view_from="LEFT"):
        rowi, coli = self._transpose_coordinates(i, j, view_from)
        return self.visited[rowi][coli]

    def mark_visited(self, i, j, view_from="LEFT"):
        rowi, coli = self._transpose_coordinates(i, j, view_from)
        self.visited[rowi][coli] = True

    def _transpose_coordinates(self, rowi, coli, view_from):
        if view_from == "UP":
            return coli, rowi
        elif view_from == "RIGHT":
            return rowi, len(self.cols[0]) - coli - 1
        elif view_from == "DOWN":
            return len(self.cols[0]) - coli - 1, rowi
        elif view_from == "LEFT":
            return rowi, coli
        else:
            raise ValueError(f"Invalid direction: {view_from}")

    def get_neighbors(self, pos: Tuple[int, int]) -> List[Tuple[int, int]]:
        neighbors = [
            (pos[0], pos[1] - 1),
            (pos[0] + 1, pos[1]),
            (pos[0], pos[1] + 1),
            (pos[0] - 1, pos[1]),
        ]

        return [pos for pos in neighbors if 0 <= pos[0] < self.rows_count() and 0 <= pos[1] < self.cols_count()]

    def find_shortest_path(
            self,
            start_position: Tuple[int, int],
            end_positions: Set[Tuple[int, int]],
            has_access):
        """ Find the shortest path between the start position and possibly multiple end positions.

        - has_access is a lambda(grid, position, neighbor_position)
        """
        shortest_routes = {start_position: 0}

        next_moves = [start_position]
        while next_moves:
            position = next_moves.pop(0)

            if position in end_positions:
                log.debug(f"End position reached in: {shortest_routes[position]}")
                continue

            route_len = shortest_routes[position]
            for neighbor in self.get_neighbors(position):
                if has_access(self, position, neighbor):
                    if self._update_shortest_routes(neighbor, route_len + 1, shortest_routes):
                        next_moves.append(neighbor)

        return min([shortest_routes[pos] for pos in end_positions if pos in shortest_routes])

    # TODO Refactor
    def _update_shortest_routes(self, pos, route_len, shortest_routes):
        if pos not in shortest_routes:
            shortest_routes[pos] = route_len
            return True
        else:
            best_so_far = shortest_routes[pos]
            if route_len < best_so_far:
                shortest_routes[pos] = route_len
                return True
            return False
