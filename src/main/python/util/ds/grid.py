from dataclasses import dataclass
from typing import List, Set, Sequence, Tuple, Generator, TypeVar, Generic
import re

from util.ds.coord import NORTH, EAST, SOUTH, WEST
from util.ds.coord import Xy, Direction
from util.functions import array2d
from util.log import log

EMPTY_SYMBOL = "."

T = TypeVar("T")


@dataclass
class GridCell(Generic[T]):

    def __init__(self, pos: Xy, value: T) -> None:
        self.pos = pos
        if isinstance(value, GridCell):
            self.value = value.value
            self.visited = value.visited
        else:
            self.value = value
            self.visited = False

    def __str__(self) -> str:
        if isinstance(self.value, list):
            if len(self.value) == 0:
                return EMPTY_SYMBOL
            if len(self.value) == 1:
                return str(self.value[0])
            else:
                return str(len(self.value))

        return str(self.value)

    def __repr__(self) -> str:
        return f"{self.value} [{self.pos}]"


class Grid(Generic[T]):

    def __init__(self, rows: List[Sequence], padding_size=0, padding_symbol=EMPTY_SYMBOL) -> None:
        """
        >>> Grid([[1,2]], padding_size=2, padding_symbol="@")
        @@@@@@
        @@@@@@
        @@12@@
        @@@@@@
        @@@@@@
        """
        assert rows, "No data"

        self.width = len(rows[0])
        self.height = len(rows)

        if padding_size > 0:
            self.width += 2 * padding_size
            self.height += 2 * padding_size
            padded_rows = []
            for y in range(self.height):
                if padding_size <= y < self.height - padding_size:
                    row = [padding_symbol] * padding_size
                    row.extend([rows[y - padding_size][x] for x in range(self.width - 2 * padding_size)])
                    row.extend([padding_symbol] * padding_size)
                else:
                    row = [padding_symbol] * self.width
                padded_rows.append(row)
            rows = padded_rows

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

    @staticmethod
    def empty(width: int, height: int, value: T = EMPTY_SYMBOL) -> "Grid[T]":
        """
        >>> print(Grid.empty(3, 2, "@"))
        @@@
        @@@
        """
        return Grid(array2d(width, height, value))

    def has(self, pos: Xy) -> bool:
        """
        >>> Grid([[1,2],[2,3]]).has(Xy(1,1))
        True
        >>> Grid([[1,2],[2,3]]).has(Xy(2,2))
        False
        """
        return 0 <= pos.x < self.width and 0 <= pos.y < self.height

    def get_cell(self, pos: Xy) -> GridCell[T]:
        """
        >>> Grid([[1,2],[2,3]]).get_cell(Xy(1,1))
        3 [(1,1)]
        """
        return self.rows[pos.y][pos.x]

    def get_value(self, pos: Xy) -> T:
        """
        >>> Grid([[1,2],[2,3]]).get_value(Xy(1,1))
        3
        """
        return self.get_cell(pos).value

    def set_value(self, pos: Xy, value: T) -> "Grid[T]":
        """
        >>> Grid([[1,2],[2,3]]).set_value(Xy(1,1), "a")
        12
        2a
        """
        self.get_cell(pos).value = value
        return self

    def get_neighbors(self, pos: Xy, side=True, diagonal=False) -> List[Xy]:
        return pos.neighbors(side, diagonal, min_x=0, max_x=self.width - 1, min_y=0, max_y=self.height - 1)

    def _get_cells_between(self, p1: Xy, p2: Xy) -> Generator[GridCell, None, None]:
        # TO-DO mode: rectangle or diagonal
        p1_x, p2_x = (p1.x, p2.x) if p1.x < p2.x else (p2.x, p1.x)
        p1_y, p2_y = (p1.y, p2.y) if p1.y < p2.y else (p2.y, p1.y)

        for y in range(p1_y, p2_y + 1):
            for x in range(p1_x, p2_x + 1):
                yield self.get_cell(Xy(x, y))

    def get_cells_between(self, p1: Xy, p2: Xy) -> List[GridCell[T]]:
        """
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).get_cells_between(Xy(1,1), Xy(0,0))
        [1 [(0,0)], 2 [(1,0)], 4 [(0,1)], 5 [(1,1)]]
        """
        return list(self._get_cells_between(p1, p2))

    def get_values_between(self, p1: Xy, p2: Xy) -> List[T]:
        """
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).get_values_between(Xy(1,1), Xy(0,0))
        [1, 2, 4, 5]
        """
        return list(map(lambda cell: cell.value, self._get_cells_between(p1, p2)))

    def set_values_between(self, p1: Xy, p2: Xy, value: T) -> "Grid[T]":
        """
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).set_values_between(Xy(1,1), Xy(0,0), "@")
        @@3
        @@6
        789
        """
        for cell in self._get_cells_between(p1, p2):
            cell.value = value
        return self

    def get_row_values(self, y: int):
        """
        >>> list(Grid([[1,2],[2,3]]).get_row_values(1))
        [2, 3]
        """
        return [cell.value for cell in self.rows[y]]

    def get_col_values(self, x: int):
        """
        >>> list(Grid([[1,2],[2,3]]).get_col_values(1))
        [2, 3]
        """
        return [cell.value for cell in self.cols[x]]

    def get_all_cells(self) -> Generator[GridCell[T], None, None]:
        """
        >>> list(Grid([[1,2],[2,3]]).get_all_cells())
        [1 [(0,0)], 2 [(1,0)], 2 [(0,1)], 3 [(1,1)]]
        """
        return self._get_cells_between(Xy(0, 0), Xy(self.width - 1, self.height - 1))

    def get_all_values(self) -> Generator[T, None, None]:
        """
        >>> list(Grid([[1,2],[2,3]]).get_all_values())
        [1, 2, 2, 3]
        """
        for cell in self.get_all_cells():
            yield cell.value

    def set_all_values(self, value: T):
        """
        >>> Grid([[1,2],[2,3]]).set_all_values("@")
        @@
        @@
        """
        self.set_values_between(Xy(0, 0), Xy(self.width - 1, self.height - 1), value)
        return self

    def get_cells_from(self, pos: Xy, direction: Direction) -> List[GridCell[T]]:
        """Get a list of cells from the given position moving into the given direction
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).get_cells_from(Xy(1,1), NORTH)
        (5 [(1,1)], 2 [(1,0)])
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).get_cells_from(Xy(1,1), EAST)
        (5 [(1,1)], 6 [(2,1)])
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).get_cells_from(Xy(1,1), SOUTH)
        (5 [(1,1)], 8 [(1,2)])
        >>> Grid([[1,2,3], [4,5,6], [7,8,9]]).get_cells_from(Xy(1,1), WEST)
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

    def find_first(self, value: T) -> Xy or None:
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

    def find_last(self, value: T) -> Xy or None:
        """
        >>> Grid([[1,2],[2,3]]).find_last(2)
        (0,1)
        >>> Grid([[1,2],[2,3]]).find_last(8)

        """
        for row in reversed(self.rows):
            for cell in reversed(row):
                if cell.value == value:
                    return cell.pos
        return None

    def find_all(self, value: T) -> List[Xy]:
        """
        >>> Grid([[1,2],[2,3]]).find_all(2)
        [(1,0), (0,1)]
        """
        result = []
        for row in self.rows:
            for cell in row:
                if cell.value == value:
                    result.append(cell.pos)
        return result

    def find_all_re(self, pattern: str) -> List[Xy]:
        """
        >>> Grid([['a','b'],['a','d']]).find_all_re('a|b')
        [(0,0), (1,0), (0,1)]
        """
        result = []
        for row in self.rows:
            for cell in row:
                if re.match(pattern, str(cell.value)):
                    result.append(cell.pos)
        return result

    def rotate_left(self) -> "Grid[T]":
        """
        >>> Grid([[1,2,3], [4,5,6]]).rotate_left()
        36
        25
        14
        """
        return Grid(list(reversed(self.cols)))

    def rotate_right(self) -> "Grid[T]":
        """
        >>> Grid([[1,2,3], [4,5,6]]).rotate_right()
        41
        52
        63
        """
        return Grid([list(reversed(col)) for col in self.cols])

    def reverse_vertical(self) -> "Grid[T]":
        """
        >>> Grid([[1,2,3], [4,5,6]]).reverse_vertical()
        321
        654
        """
        return Grid([list(reversed(rows)) for rows in self.rows])

    def reverse_horizontal(self) -> "Grid[T]":
        """
        >>> Grid([[1,2,3], [4,5,6]]).reverse_horizontal()
        456
        123
        """
        return Grid(list(reversed(self.rows)))

    def format(self, show_visited=False, cell_separator: str = "") -> str:
        lines = []
        for row in self.rows:
            cells = []
            for cell in row:
                visited = ""
                if show_visited:
                    visited = "T" if cell.visited else "F"
                cells.append(f"{str(cell)}{visited}")
            lines.append(cell_separator.join(cells))
        return "\n".join(lines)

    def __repr__(self) -> str:
        return self.format()

    # business methods >>>

    def walk(self,
             pos: Xy,
             steps: int,
             direction: Direction,
             stop_value=None,
             skip_value=None,
             wrap_around=False,
             trace=False) -> "Grid[T]":

        assert self.has(pos), "Start position is not on the grid!"

        step_counter = 1
        next_pos = pos
        while step_counter <= steps:
            if trace:
                self.set_value(pos, direction.print_symbol)

            next_pos = next_pos.neighbor(direction)

            if not self.has(next_pos):
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


class LightGrid:
    """Lightweight grid - less fancy, much faster"""

    def __init__(self, rows: list[str]) -> None:
        assert len(rows) > 0
        self.rows = [list(row) for row in rows]
        self.width = len(rows[0])
        self.height = len(rows)

    @staticmethod
    def empty(width: int, height: int, value: T = EMPTY_SYMBOL) -> "LightGrid":
        """
        >>> print(Grid.empty(3, 2, "@"))
        @@@
        @@@
        """
        return LightGrid(array2d(width, height, value))

    def get_all_positions(self) -> tuple[int, int]:  # TODO test for perf
        for y in range(self.height):
            for x in range(self.width):
                yield x, y

    def get_neighbors(self, pos: tuple[int, int]) -> list[tuple[int, int]]:
        x, y = pos
        neighbors = []
        if y > 0:
            neighbors.append((x, y - 1))
        if x < self.width - 1:
            neighbors.append((x + 1, y))
        if y < self.height - 1:
            neighbors.append((x, y + 1))
        if x > 0:
            neighbors.append((x - 1, y))
        return neighbors

    def get(self, pos: tuple[int, int]):
        x, y = pos
        return self.rows[y][x]

    def set(self, pos: tuple[int, int], value):
        x, y = pos
        self.rows[y][x] = value
        return self

    def __getitem__(self, y):
        return self.rows[y]

    def __str__(self) -> str:
        return "\n".join(["".join(str(row)) for row in self.rows])
