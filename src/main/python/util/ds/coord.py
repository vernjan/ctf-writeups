import re
from dataclasses import dataclass
from math import inf
from typing import List


@dataclass(frozen=True)
class Direction:
    value: str
    print_symbol: str

    def turn_left(self) -> "Direction":
        """
        >>> UP.turn_left()
        left
        >>> UP.turn_left().turn_left()
        down
        >>> RIGHT.turn_left()
        up
        >>> RIGHT.turn_left().turn_left()
        left
        """
        index = DIRECTIONS.index(self)
        return DIRECTIONS[(index - 1) % len(DIRECTIONS)]

    def turn_right(self) -> "Direction":
        """
        >>> UP.turn_right()
        right
        >>> UP.turn_right().turn_right()
        down
        >>> RIGHT.turn_right()
        down
        >>> RIGHT.turn_right().turn_right()
        left
        """
        index = DIRECTIONS.index(self)
        return DIRECTIONS[(index + 1) % len(DIRECTIONS)]

    def turn_around(self) -> "Direction":
        return self.turn_left().turn_left()

    def __str__(self) -> str:
        return self.print_symbol

    def __repr__(self) -> str:
        return self.value


UP = Direction("up", "^")
RIGHT = Direction("right", ">")
DOWN = Direction("down", "v")
LEFT = Direction("left", "<")

DIRECTIONS = [UP, RIGHT, DOWN, LEFT]


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

    def neighbor(self, direction: Direction):
        move = getattr(self, direction.value)
        return move()

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
