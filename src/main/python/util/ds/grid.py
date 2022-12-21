from dataclasses import dataclass
from typing import List, Set, Sequence, Any

from util.ds.coord import Xy
from util.functions import array2d
from util.log import log


@dataclass
class GridCell:

    def __init__(self, pos: Xy, value: Any) -> None:
        self.pos = pos
        if isinstance(value, GridCell):
            self.value = value.value
            self.visited = value.visited
        else:
            self.value = value
            self.visited = False

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"{self.value} [{self.pos}]"


class Grid:
    DIRECTIONS = ["NORTH", "EAST", "SOUTH", "WEST"]

    def __init__(self, rows: List[Sequence]):
        assert rows, "No data"

        self.width = len(rows[0])
        self.height = len(rows)

        # TODO Make private! Maybe add getter which returns frozenlist of frozen lists
        self.rows: List[List[GridCell]] = []
        for y in range(self.height):
            row = [GridCell(Xy(x, y), rows[y][x]) for x in range(self.width)]
            self.rows.append(row)

        # TODO Make private! Maybe add getter which returns frozenlist of frozen lists
        self._cols: List[List[GridCell]] = []
        for x in range(self.width):
            col = [self.rows[y][x] for y in range(self.height)]
            self._cols.append(col)

    @classmethod
    def empty(cls, width, height, value="."):
        """
        >>> print(Grid.empty(3, 2, "@"))
        @@@
        @@@
        """
        return Grid(array2d(width, height, value))

    # TODO Remove
    def __getitem__(self, ri) -> List:
        return self.rows[ri]

    def __repr__(self) -> str:
        return self.format()

    def format(self, visited=False, separator=""):
        lines = []
        for row in self.rows:
            cells = []
            for cell in row:
                v = ""
                if visited:
                    v = "T" if cell.visited else "F"
                cells.append(f"{cell.value}{v}")
            lines.append(separator.join(cells))
        return "\n".join(lines)

    def fill_all(self, value):
        """
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).fill_all("@")
        @@@
        @@@
        @@@
        """
        for row in self.rows:
            for cell in row:
                cell.value = value
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
            p1_x, p2_x = (p1.x, p2.x) if p1.x < p2.x else (p2.x, p1.x)  # left to right, right to left
            for x in range(p1_x, p2_x + 1):
                self.set(Xy(x, p1.y), value)

        elif p1.x == p2.x:
            p1_y, p2_y = (p1.y, p2.y) if p1.y < p2.y else (p2.y, p1.y)
            for y in range(p1_y, p2_y + 1):
                self.set(Xy(p1.x, y), value)

        else:
            # TO-DO diagonal fill, ...
            assert False, "Not yet implemented"

        return self

    def find_first(self, value) -> GridCell or None:
        """
        >>> Grid([[1,2],[2,3]]).find_first(2)
        2 [(1,0)]
        >>> Grid([[1,2],[2,3]]).find_first(8)

        """
        for row in self.rows:
            for cell in row:
                if cell.value == value:
                    return cell
        return None

    def find_all(self, value) -> List[GridCell]:
        """
        >>> Grid([[1,2],[2,3]]).find_all(2)
        [2 [(1,0)], 2 [(0,1)]]
        """
        result = []
        for row in self.rows:
            for cell in row:
                if cell.value == value:
                    result.append(cell)
        return result

    def at(self, pos: Xy) -> GridCell:
        """
        >>> Grid([[1,2],[2,3]]).at(Xy(1,1)).value
        3
        """
        return self[pos.y][pos.x]

    def set(self, pos: Xy, value):
        """
        >>> Grid([[1,2],[2,3]]).set(Xy(1,1), "a")
        12
        2a
        """
        self.at(pos).value = value
        return self

    # TODO Unite slicing and filling: slice_from, slice_between + fill_from, fill_between
    def slice_at(self, pos: Xy, direction) -> List[GridCell]:
        """Get a grid slice (list) from the given position moving into the given direction
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(Xy(1,1), "NORTH")
        [5 [(1,1)], 2 [(1,0)]]
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(Xy(1,1), "EAST")
        [5 [(1,1)], 6 [(2,1)]]
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(Xy(1,1), "SOUTH")
        [5 [(1,1)], 8 [(1,2)]]
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(Xy(1,1), "WEST")
        [5 [(1,1)], 4 [(0,1)]]
        """

        if direction == "NORTH":
            return self._cols[pos.x][pos.y::-1]
        elif direction == "EAST":
            return self.rows[pos.y][pos.x:]
        elif direction == "SOUTH":
            return self._cols[pos.x][pos.y:]
        elif direction == "WEST":
            return self.rows[pos.y][pos.x::-1]
        else:
            raise ValueError(f"Invalid direction: {direction}")

    def rotate_left(self) -> "Grid":
        """
        >>> Grid([[1,2,3], [4,5,6]]).rotate_left()
        36
        25
        14
        """
        return Grid(list(reversed(self._cols)))

    def rotate_right(self) -> "Grid":
        """
        >>> Grid([[1,2,3], [4,5,6]]).rotate_right()
        41
        52
        63
        """
        return Grid([list(reversed(col)) for col in self._cols])

    def reverse_vertical(self) -> "Grid":
        """
        >>> Grid([[1,2,3], [4,5,6]]).reverse_vertical()
        321
        654
        """
        return Grid([list(reversed(rows)) for rows in self.rows])

    def reverse_horizontal(self) -> "Grid":
        """
        >>> Grid([[1,2,3], [4,5,6]]).reverse_horizontal()
        456
        123
        """
        return Grid(list(reversed(self.rows)))

    def get_neighbors(self, pos: Xy, side=True, diagonal=False) -> List[Xy]:
        return pos.neighbors(side, diagonal, min_x=0, max_x=self.width - 1, min_y=0, max_y=self.height - 1)

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
