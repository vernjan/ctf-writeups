import logging
import re
import sys
from dataclasses import dataclass
from functools import cached_property

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


@dataclass(frozen=True)
class Shape:
    base: str

    @cached_property
    def variants(self):
        """
        All possible flips and rotations
        """
        variants = set()

        # TODO JVe Make this generic and move into utils

        variants.add(self)
        # rot 90
        variants.add(Shape(
            self.base[6] + self.base[3] + self.base[0] +
            self.base[7] + self.base[4] + self.base[1] +
            self.base[8] + self.base[5] + self.base[2]))
        # rot 180
        variants.add(Shape(
            self.base[8] + self.base[7] + self.base[6] +
            self.base[5] + self.base[4] + self.base[3] +
            self.base[2] + self.base[1] + self.base[0]))
        # rot 270
        variants.add(Shape(
            self.base[2] + self.base[5] + self.base[8] +
            self.base[1] + self.base[4] + self.base[7] +
            self.base[0] + self.base[3] + self.base[6]))

        # flip
        variants.add(Shape(
            self.base[2] + self.base[1] + self.base[0] +
            self.base[5] + self.base[4] + self.base[3] +
            self.base[8] + self.base[7] + self.base[6]))
        # rot 90
        variants.add(Shape(
            self.base[0] + self.base[3] + self.base[6] +
            self.base[1] + self.base[4] + self.base[7] +
            self.base[2] + self.base[5] + self.base[8]))
        # rot 180
        variants.add(Shape(
            self.base[6] + self.base[7] + self.base[8] +
            self.base[3] + self.base[4] + self.base[5] +
            self.base[0] + self.base[1] + self.base[2]))
        # rot 270
        variants.add(Shape(
            self.base[8] + self.base[5] + self.base[2] +
            self.base[7] + self.base[4] + self.base[1] +
            self.base[6] + self.base[3] + self.base[0]))

        return variants

    def __str__(self):
        return self.base[:3] + "\n" + self.base[3:6] + "\n" + self.base[6:] + "\n"


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    2
    """
    gift_patterns: list[str] = []
    gift_pattern: str = ""
    for line in lines:
        if re.match("[#.]{3}", line):
            gift_pattern += line
        elif len(line) == 0:
            gift_patterns.append(gift_pattern)
            gift_pattern = ""
        else:
            m = re.match("([0-9]+)x([0-9]+):(.*)", line)
            if m:
                # TODO JVe Prepare rotations and flips
                shapes: list[Shape] = list(map(Shape, gift_patterns))

                for s in shapes:
                    log.debug(f"Shape {s.base}:")
                    for sv in s.variants:
                        log.debug(sv)

                width = m.group(1)
                height = m.group(2)
                gifts_histo = list(map(int, m.group(3).split()))
                _solve_task(width, height, gifts_histo, shapes)


def _solve_task(width: str, height: str, gifts_histo: list[int], shapes: list[Shape]):
    log.debug(f"w={width}, h={height}, gh={gifts_histo}, shapes={shapes}")
    sys.exit(0)


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))

    """
    for line in lines:
        pass


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=None)
    timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=None)
