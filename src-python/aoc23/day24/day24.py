import logging
from dataclasses import dataclass
from typing import List, Optional, Tuple

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xyz
from util.log import log


@dataclass(frozen=True)
class Hailstone:
    pos: Xyz
    diff: Xyz
    a: int
    b: int

    def __repr__(self) -> str:
        return f"{self.pos} -> y = {self.a}x + {self.b}"

    def intersection(self, other: "Hailstone") -> Optional[Tuple[float, float]]:
        if self.a == other.a:
            return None
        temp1 = other.b - self.b
        temp2 = self.a - other.a
        x = temp1 / temp2
        y = self.a * x + self.b
        return x, y


def star1(lines: list[str], test_area_min=7, test_area_max=27):
    """
    >>> star1(read_test_input(__file__))
    2
    """
    hailstones = _parse_hailstones(lines)

    total_intersections = 0
    for i, h1 in enumerate(hailstones):
        for h2 in hailstones[i + 1:]:
            log.debug(f"Checking {h1} vs. {h2}")
            intersection = h1.intersection(h2)
            if intersection:
                x, y = intersection
                log.debug(f"{h1.a}x + {h1.b} = {h2.a}x + {h2.b} -> x = {x}, y = {y}")
                if test_area_min <= x <= test_area_max and test_area_min <= y <= test_area_max:
                    if _is_future_intersection(h1, x) and _is_future_intersection(h2, x):
                        total_intersections += 1
    return total_intersections


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))

    """
    for line in lines:
        pass


def _is_future_intersection(h, x):
    return (h.diff.x < 0 and x < h.pos.x) or (h.diff.x > 0 and x > h.pos.x)


def _parse_hailstones(lines) -> List[Hailstone]:
    hailstones = []
    for line in lines:
        pos, diff = map(Xyz.parse, line.split("@"))
        # y = ax + b
        a = diff.y / diff.x  # TODO more object oriented?
        b = pos.y - a * pos.x
        hailstone = Hailstone(pos, diff, a, b)
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
