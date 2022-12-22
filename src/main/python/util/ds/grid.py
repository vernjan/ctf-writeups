from dataclasses import dataclass
from typing import List, Set, Sequence, Any, Tuple

from util.ds.coord import Xy, Direction
from util.functions import array2d
from util.log import log

NORTH = "north"
EAST = "east"
SOUTH = "south"
WEST = "west"


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


# TODO new method value_at, values_slice, between
# TODO Unite slicing and filling: slice_from, slice_between + fill_from, fill_between
class Grid:
    DIRECTIONS = [NORTH, EAST, SOUTH, WEST]  # TODO Remove me, use coord.DIRECTIONS

    def __init__(self, rows: List[Sequence]):
        assert rows, "No data"

        self.width = len(rows[0])
        self.height = len(rows)

        rows_list = []
        for y in range(self.height):
            row = tuple([GridCell(Xy(x, y), rows[y][x]) for x in range(self.width)])
            rows_list.append(row)
        self.rows: Tuple = tuple(rows_list)

        cols_list = []
        for x in range(self.width):
            col = tuple([self.rows[y][x] for y in range(self.height)])
            cols_list.append(col)
        self.cols: Tuple = tuple(cols_list)

    @classmethod
    def empty(cls, width, height, value="."):
        """
        >>> print(Grid.empty(3, 2, "@"))
        @@@
        @@@
        """
        return Grid(array2d(width, height, value))

    def __repr__(self) -> str:
        return self.format()

    def format(self, show_visited=False, cell_separator=""):
        lines = []
        for row in self.rows:
            cells = []
            for cell in row:
                v = ""
                if show_visited:
                    v = "T" if cell.visited else "F"
                cells.append(f"{cell.value}{v}")
            lines.append(cell_separator.join(cells))
        return "\n".join(lines)

    def get(self, pos: Xy) -> GridCell:
        """
        >>> Grid([[1,2],[2,3]]).get(Xy(1,1))
        3 [(1,1)]
        """
        return self.rows[pos.y][pos.x]

    def get_value(self, pos: Xy) -> Any:
        """
        >>> Grid([[1,2],[2,3]]).get_value(Xy(1,1))
        3
        """
        return self.get(pos).value

    def set_value(self, pos: Xy, value):
        """
        >>> Grid([[1,2],[2,3]]).set_value(Xy(1,1), "a")
        12
        2a
        """
        self.get(pos).value = value
        return self

    # def set_row_values(self, y, start=0, end=):

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
                self.set_value(Xy(x, p1.y), value)

        elif p1.x == p2.x:
            p1_y, p2_y = (p1.y, p2.y) if p1.y < p2.y else (p2.y, p1.y)
            for y in range(p1_y, p2_y + 1):
                self.set_value(Xy(p1.x, y), value)

        else:
            # TO-DO diagonal fill, ... or square?
            assert False, "Not yet implemented"

        return self

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

    def find_first(self, value) -> Xy or None:
        """
        >>> Grid([[1,2],[2,3]]).find_first(2)
        (1,0)
        >>> Grid([[1,2],[2,3]]).find_first(8)

        """
        for row in self.rows:
            for cell in row:
                if cell.value == value:
                    return cell.pos
        return None

    def find_all(self, value) -> List[Xy]:
        """
        >>> Grid([[1,2],[2,3]]).find_all(2)
        [(1,0)], (0,1)]
        """
        result = []
        for row in self.rows:
            for cell in row:
                if cell.value == value:
                    result.append(cell.pos)
        return result

    def slice_at(self, pos: Xy, direction) -> List[GridCell]:
        """Get a grid slice (list) from the given position moving into the given direction
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(Xy(1,1), NORTH)
        (5 [(1,1)], 2 [(1,0)])
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(Xy(1,1), EAST)
        (5 [(1,1)], 6 [(2,1)])
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(Xy(1,1), SOUTH)
        (5 [(1,1)], 8 [(1,2)])
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).slice_at(Xy(1,1), WEST)
        (5 [(1,1)], 4 [(0,1)])
        """

        if direction == NORTH:
            return self.cols[pos.x][pos.y::-1]
        elif direction == EAST:
            return self.rows[pos.y][pos.x:]
        elif direction == SOUTH:
            return self.cols[pos.x][pos.y:]
        elif direction == WEST:
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
        return Grid(list(reversed(self.cols)))

    def rotate_right(self) -> "Grid":
        """
        >>> Grid([[1,2,3], [4,5,6]]).rotate_right()
        41
        52
        63
        """
        return Grid([list(reversed(col)) for col in self.cols])

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

    def move(self,
             pos: Xy,
             steps: int,
             direction: Direction,
             stop_value=None,
             skip_value=None,
             wrap_around=False,
             trace=False) -> "Grid":

        assert self._is_on_grid(pos), "Start position is not on the grid!"

        step_counter = 1
        next_pos = pos
        while step_counter <= steps:
            if trace:
                self.set_value(pos, direction.print_symbol)

            next_pos = next_pos.neighbor(direction)

            if not self._is_on_grid(next_pos):
                if wrap_around:
                    next_pos = Xy(next_pos.x % self.width, next_pos.y % self.height)
                else:
                    break

            if self.get_value(next_pos) == stop_value:
                break

            if self.get_value(next_pos) != skip_value:
                step_counter += 1
                pos = next_pos
            else:
                next_pos = next_pos

        self.set_value(pos, "x")
        return pos

    def _is_on_grid(self, pos: Xy):
        return 0 <= pos.x < self.width and 0 <= pos.y < self.height


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
