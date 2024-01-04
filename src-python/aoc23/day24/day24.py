import logging
import random
from dataclasses import dataclass
from decimal import *
from functools import cached_property
from typing import List, Optional, Tuple, Type, TypeVar

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xy, Xyz
from util.log import log

H = TypeVar("H")


@dataclass(frozen=True)
class Hailstone2D:
    """
    y = ax + b
    """
    pos: Xy
    diff: Xy

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

    # print equations for any 3 hailstones
    random.shuffle(hailstones)
    for i, h in enumerate(hailstones[:3]):
        t = chr(ord('t') + i)  # time
        log.info(f"x + {t}*a = {h.pos.x} {h.diff.x:+}*{t}")
        log.info(f"y + {t}*b = {h.pos.y} {h.diff.y:+}*{t}")
        log.info(f"z + {t}*c = {h.pos.z} {h.diff.z:+}*{t}")

    # solve equations, e.g. https://quickmath.com/webMathematica3/quickmath/equations/solve/advanced.jsp

    return 828418331313365


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
    # Star 2: 828418331313365
