import logging
from dataclasses import dataclass
from decimal import *
from functools import cached_property
from typing import List, Optional, Tuple, Type, TypeVar

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xy, Xyz
from util.log import log

H = TypeVar("H")


# https://www.karlin.mff.cuni.cz/~portal/analyticka_geometrie/prostor.php?kapitola=vzajemnaPoloha

@dataclass(frozen=True)
class Hailstone2D:
    """
    y = ax + b
    TODO Generalize to ax + by + c = 0, remove __post_init__
    """
    pos: Xy
    diff: Xy

    def __post_init__(self):
        if self.diff.x == 0:
            """A function from a set X to a set Y assigns to each element of X exactly one element of Y."""
            raise ValueError("Not a function by definition")

    def __repr__(self) -> str:
        return f"{self.pos} -> y = {self.a}x + {self.b}"

    @cached_property
    def a(self):
        return self.diff.y / self.diff.x

    @cached_property
    def b(self):
        return self.pos.y - self.a * self.pos.x

    def intersection(self, other: "Hailstone2D") -> Optional[Tuple[float, float]]:
        """
        >>> Hailstone2D(Xy(0, 0), Xy(1,  1)).intersection(Hailstone2D(Xy(0, 1), Xy(1, 0)))
        (1.0, 1.0)
        >>> Hailstone2D(Xy(19, 13), Xy(-2,  1)).intersection(Hailstone2D(Xy(18, 19), Xy(-1, -1)))
        (14.333333333333334, 15.333333333333334)
        """
        if self.a == other.a:
            return None  # parallel or exactly the same
        temp1 = other.b - self.b
        temp2 = self.a - other.a
        x = Decimal(temp1) / Decimal(temp2)
        y = Decimal(self.a) * x + Decimal(self.b)
        return float(x), float(y)


@dataclass(frozen=True)
class Hailstone3D:
    pos: Xyz
    diff: Xyz

    def intersection(self, other: "Hailstone3D") -> Optional[Tuple[float, float, float]]:
        """
        >>> Hailstone3D(Xyz(0, 0, 0), Xyz(1,  1,  1)).intersection(Hailstone3D(Xyz(0, 0, 1), Xyz(1,  1,  -1)))
        (0.5, 0.5, 0.5)
        >>> Hailstone3D(Xyz(5, 2, -1), Xyz(1,  -2,  -3)).intersection(Hailstone3D(Xyz(2, 0, 4), Xyz(1,  2,  -1)))
        (4.0, 4.0, 2.0)
        """
        h1_xy = Hailstone2D(Xy(self.pos.x, self.pos.y), Xy(self.diff.x, self.diff.y))
        h2_xy = Hailstone2D(Xy(other.pos.x, other.pos.y), Xy(other.diff.x, other.diff.y))
        intersection_xy = h1_xy.intersection(h2_xy)
        log.debug(f"Intersection XY: {intersection_xy}")
        if not intersection_xy:
            return None

        h1_yz = Hailstone2D(Xy(self.pos.y, self.pos.z), Xy(self.diff.y, self.diff.z))
        h2_yz = Hailstone2D(Xy(other.pos.y, other.pos.z), Xy(other.diff.y, other.diff.z))
        intersection_yz = h1_yz.intersection(h2_yz)
        log.debug(f"Intersection YZ: {intersection_yz}")
        if not intersection_yz:
            return None

        h1_zx = Hailstone2D(Xy(self.pos.z, self.pos.x), Xy(self.diff.z, self.diff.x))
        h2_zx = Hailstone2D(Xy(other.pos.z, other.pos.x), Xy(other.diff.z, other.diff.x))
        intersection_zx = h1_zx.intersection(h2_zx)
        log.debug(f"Intersection ZX: {intersection_zx}")
        if not intersection_zx:
            return None

        if intersection_xy[1] != intersection_yz[0]:
            return None

        # assert intersection_xy[1] == intersection_yz[0], f"{intersection_xy[1]} != {intersection_yz[0]}"
        # assert intersection_yz[1] == intersection_zx[0], f"{intersection_yz[1]} != {intersection_zx[0]}"
        # assert intersection_zx[1] == intersection_xy[0], f"{intersection_zx[1]} != {intersection_xy[0]}"

        return intersection_xy[0], intersection_xy[1], intersection_yz[1]


def star1(lines: list[str], test_area_min=7, test_area_max=27):
    """
    >>> star1(read_test_input(__file__))
    2
    """
    hailstones = _parse_hailstones(lines, Hailstone2D)

    def is_future_intersection(h):
        return (h.diff.x < 0 and x < h.pos.x) or (h.diff.x > 0 and x > h.pos.x)  # (h.diff.x < 0) ^ (x > h.pos.x)

    total_intersections = 0
    for i, h1 in enumerate(hailstones):
        for h2 in hailstones[i + 1:]:
            log.debug(f"Checking {h1} vs. {h2}")
            intersection = h1.intersection(h2)
            if intersection:
                x, y = intersection
                log.debug(f"{h1.a}x + {h1.b} = {h2.a}x + {h2.b} -> x = {x}, y = {y}")
                if test_area_min <= x <= test_area_max and test_area_min <= y <= test_area_max:
                    if is_future_intersection(h1) and is_future_intersection(h2):
                        total_intersections += 1
    return total_intersections


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    47
    """
    hailstones = _parse_hailstones(lines, Hailstone3D)

    for h in hailstones:
        xs = []
        ys = []
        zs = []
        for i in range(10):
            xs.append(h.pos.x + h.diff.x * i)
            ys.append(h.pos.y + h.diff.y * i)
            zs.append(h.pos.z + h.diff.z * i)
        log.debug(f"{xs}, {ys}, {zs}")

    # for i, h1 in enumerate(hailstones):
    #     for h2 in hailstones[i + 1:]:
    #         log.debug(f"Checking {h1} vs. {h2}")
    #         intersection = h1.intersection(h2)
    #         if intersection:
    #             x, y, z = intersection
    #             log.debug(f"Intersection at x = {x}, y = {y}, z = {z}")

    return -1

# Hailstone Hailstone3D(pos=(19,13,30), diff=(-2,1,-2))
# Hailstone Hailstone3D(pos=(18,19,22), diff=(-1,-1,-2))
# Hailstone Hailstone3D(pos=(20,25,34), diff=(-2,-2,-4))
# Hailstone Hailstone3D(pos=(12,31,28), diff=(-1,-2,-1))
# Hailstone Hailstone3D(pos=(20,19,15), diff=(1,-5,-3))
# [19, 17, 15, 13, 11, 9, 7, 5, 3, 1],      [13, 14, 15, 16, 17, 18, 19, 20, 21, 22],   [30, 28, 26, 24, 22, 20, 18, 16, 14, 12]
# [18, 17, 16, 15, 14, 13, 12, 11, 10, 9],  [19, 18, 17, 16, 15, 14, 13, 12, 11, 10],   [22, 20, 18, 16, 14, 12, 10, 8, 6, 4]
# [20, 18, 16, 14, 12, 10, 8, 6, 4, 2],     [25, 23, 21, 19, 17, 15, 13, 11, 9, 7],     [34, 30, 26, 22, 18, 14, 10, 6, 2, -2]
# [12, 11, 10, 9, 8, 7, 6, 5, 4, 3],        [31, 29, 27, 25, 23, 21, 19, 17, 15, 13],   [28, 27, 26, 25, 24, 23, 22, 21, 20, 19]
# [20, 21, 22, 23, 24, 25, 26, 27, 28, 29], [19, 14, 9,  4, -1, -6, -11, -16, -21, -26], [15, 12, 9, 6, 3, 0, -3, -6, -9, -12]

def _parse_hailstones(lines, cls: Type[H]) -> List[H]:
    hailstones = []
    for line in lines:
        pos, diff = map(Xyz.parse, line.split("@"))
        hailstone = cls(pos, diff)
        hailstones.append(hailstone)
        log.debug(f"Hailstone {hailstone}")
    return hailstones


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__),
                                      test_area_min=200000000000000, test_area_max=400000000000000))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 26657
    # Star 2:
