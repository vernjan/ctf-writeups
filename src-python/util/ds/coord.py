import re
from dataclasses import dataclass
from functools import cached_property
from math import inf
from typing import List

from sortedcontainers import SortedSet


@dataclass(frozen=True)
class Direction:
    value: str
    print_symbol: str

    def turn_left(self) -> "Direction":
        """
        >>> NORTH.turn_left()
        west
        >>> NORTH.turn_left().turn_left()
        south
        >>> EAST.turn_left()
        north
        >>> EAST.turn_left().turn_left()
        west
        """
        index = DIRECTIONS.index(self)
        return DIRECTIONS[(index - 1) % len(DIRECTIONS)]

    def turn_right(self) -> "Direction":
        """
        >>> NORTH.turn_right()
        east
        >>> NORTH.turn_right().turn_right()
        south
        >>> EAST.turn_right()
        south
        >>> EAST.turn_right().turn_right()
        west
        """
        index = DIRECTIONS.index(self)
        return DIRECTIONS[(index + 1) % len(DIRECTIONS)]

    def turn_around(self) -> "Direction":
        return self.turn_left().turn_left()

    def __str__(self) -> str:
        return self.print_symbol

    def __repr__(self) -> str:
        return self.value


NORTH = Direction("north", "↑")
EAST = Direction("east", "→")
SOUTH = Direction("south", "↓")
WEST = Direction("west", "←")
NORTH_EAST = Direction("north_east", "⬈")
SOUTH_EAST = Direction("south_east", "⬊")
SOUTH_WEST = Direction("south_west", "⬋")
NORTH_WEST = Direction("north_west", "⬉")

DIRECTIONS = [NORTH, EAST, SOUTH, WEST]


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

    def __lt__(self, other):
        if self.x != other.x:
            return self.x < other.x
        return self.y < other.y

    def north(self):
        return Xy(self.x, self.y - 1)

    def east(self):
        return Xy(self.x + 1, self.y)

    def south(self):
        return Xy(self.x, self.y + 1)

    def west(self):
        return Xy(self.x - 1, self.y)

    def north_east(self):
        return Xy(self.x + 1, self.y - 1)

    def south_east(self):
        return Xy(self.x + 1, self.y + 1)

    def south_west(self):
        return Xy(self.x - 1, self.y + 1)

    def north_west(self):
        return Xy(self.x - 1, self.y - 1)

    def neighbor(self, direction: Direction, dist: int = 1) -> "Xy":
        if direction == NORTH:
            return Xy(self.x, self.y - dist)
        elif direction == EAST:
            return Xy(self.x + dist, self.y)
        elif direction == SOUTH:
            return Xy(self.x, self.y + dist)
        elif direction == WEST:
            return Xy(self.x - dist, self.y)
        elif direction == NORTH_EAST:
            return Xy(self.x + dist, self.y - dist)
        elif direction == SOUTH_EAST:
            return Xy(self.x + dist, self.y + dist)
        elif direction == SOUTH_WEST:
            return Xy(self.x - dist, self.y + dist)
        elif direction == NORTH_WEST:
            return Xy(self.x - dist, self.y - dist)
        else:
            raise ValueError(f"Unknown direction: {direction}")

    def neighbors(self, side=True, diagonal=False, min_x=-inf, max_x=inf, min_y=-inf, max_y=inf) -> List["Xy"]:
        """
        >>> Xy(0,1).neighbors()
        [(0,0), (1,1), (0,2), (-1,1)]
        >>> Xy(0,1).neighbors(min_x=0, max_x=2, min_y=0, max_y=2)
        [(0,0), (1,1), (0,2)]
        """
        neighbors = []
        if side:
            neighbors.extend([self.north(), self.east(), self.south(), self.west()])
        if diagonal:
            neighbors.extend([self.north_east(), self.south_east(), self.south_west(), self.north_west()])

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

    def __lt__(self, other):
        if self.x != other.x:
            return self.x < other.x
        if self.y != other.y:
            return self.y < other.y
        return self.z < other.z

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
            assert False, "Not yet implemented"
        if corner:
            assert False, "Not yet implemented"

        return [xyz for xyz in neighbors if
                min_x <= xyz.x <= max_x and min_y <= xyz.y <= max_y and min_z <= xyz.z <= max_z]


@dataclass(frozen=True)
class Cube:
    p1: Xyz
    p2: Xyz

    def __repr__(self):
        return f"{self.p1}~{self.p2}"

    def z_inc(self, step: int = 1) -> "Cube":
        return Cube(Xyz(self.p1.x, self.p1.y, self.p1.z + step), Xyz(self.p2.x, self.p2.y, self.p2.z + step))

    def z_dec(self, step: int = -1) -> "Cube":
        return Cube(Xyz(self.p1.x, self.p1.y, self.p1.z - step), Xyz(self.p2.x, self.p2.y, self.p2.z - step))

    @cached_property
    def positions(self) -> SortedSet[Xyz]:
        """
        >>> Cube(Xyz(0,0,0), Xyz(0,0,0)).positions
        SortedSet([(0,0,0)])
        >>> Cube(Xyz(0,0,0), Xyz(2,0,0)).positions
        SortedSet([(0,0,0), (1,0,0), (2,0,0)])
        >>> Cube(Xyz(0,0,0), Xyz(1,1,1)).positions
        SortedSet([(0,0,0), (0,0,1), (0,1,0), (0,1,1), (1,0,0), (1,0,1), (1,1,0), (1,1,1)])
        """
        positions = SortedSet()
        for x in range(self.p1.x, self.p2.x + 1):
            for y in range(self.p1.y, self.p2.y + 1):
                for z in range(self.p1.z, self.p2.z + 1):
                    positions.add(Xyz(x, y, z))
        return positions

    # TODO Could be generic for all axis
    # TODO fix doctest for cached property
    @cached_property
    def xy_positions(self) -> SortedSet[Xy]:
        """
        >>> Cube(Xyz(0,0,0), Xyz(0,0,0)).xy_positions
        SortedSet([(0,0)])
        >>> Cube(Xyz(0,0,0), Xyz(2,0,0)).xy_positions
        SortedSet([(0,0), (1,0), (2,0)])
        >>> Cube(Xyz(0,0,0), Xyz(1,1,1)).xy_positions
        SortedSet([(0,0), (0,1), (1,0), (1,1)])
        """
        positions = SortedSet()
        for x in range(self.p1.x, self.p2.x + 1):
            for y in range(self.p1.y, self.p2.y + 1):
                positions.add(Xy(x, y))
        return positions
