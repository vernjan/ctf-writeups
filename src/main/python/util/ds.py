import re
from dataclasses import dataclass
from math import inf
from typing import List, Set, Sequence, Any, Dict

from util.functions import array2d
from util.log import log


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


@dataclass
class FlatNode:
    left: str
    right: str
    value: Any


@dataclass
class TreeNode:
    name: str
    left: "TreeNode" or None
    right: "TreeNode" or None
    value: Any
    depth: int

    @staticmethod
    def from_nodes(nodes: Dict[str, FlatNode], root_name: str, depth: int = 0) -> "TreeNode" or None:
        if root_name is None:
            return None

        node = nodes[root_name]
        assert node, f"Node {root_name} doesn't exist"

        if node.left is None and node.right is None:
            return TreeNode(root_name, None, None, node.value, depth)

        left = TreeNode.from_nodes(nodes, node.left, depth + 1)
        right = TreeNode.from_nodes(nodes, node.right, depth + 1)
        return TreeNode(root_name, left, right, node.value, depth)

    def find_node(self, name: str) -> "TreeNode" or None:
        return TreeNode._find_node(self, name)

    @staticmethod
    def _find_node(node: "TreeNode", name: str) -> "TreeNode" or None:
        if node is None:
            return None
        if node.name == name:
            return node
        left = TreeNode._find_node(node.left, name)
        if left:
            return left
        return TreeNode.find_node(node.right, name)

    def __str__(self) -> str:
        padding = "--" * (self.depth + 1)
        left = ""
        if self.left:
            left = f"\n{padding} {self.left}"
        right = ""
        if self.right:
            right = f"\n{padding} {self.right}"
        return f"{self.name}: {self.value}{left}{right}"
