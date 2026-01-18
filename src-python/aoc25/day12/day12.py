import logging
import random
import re
import string
from dataclasses import dataclass
from functools import cached_property

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


@dataclass(frozen=True)
class GiftPattern:
    base: str

    # TODO JVe Use this ???
    @cached_property
    def variants(self):
        """
        All possible flips and rotations
        """
        variants = set()

        # TODO JVe Make this generic and move into utils

        variants.add(self)
        # rot 90
        variants.add(GiftPattern(
            self.base[6] + self.base[3] + self.base[0] +
            self.base[7] + self.base[4] + self.base[1] +
            self.base[8] + self.base[5] + self.base[2]))
        # rot 180
        variants.add(GiftPattern(
            self.base[8] + self.base[7] + self.base[6] +
            self.base[5] + self.base[4] + self.base[3] +
            self.base[2] + self.base[1] + self.base[0]))
        # rot 270
        variants.add(GiftPattern(
            self.base[2] + self.base[5] + self.base[8] +
            self.base[1] + self.base[4] + self.base[7] +
            self.base[0] + self.base[3] + self.base[6]))

        # flip
        variants.add(GiftPattern(
            self.base[2] + self.base[1] + self.base[0] +
            self.base[5] + self.base[4] + self.base[3] +
            self.base[8] + self.base[7] + self.base[6]))
        # rot 90
        variants.add(GiftPattern(
            self.base[0] + self.base[3] + self.base[6] +
            self.base[1] + self.base[4] + self.base[7] +
            self.base[2] + self.base[5] + self.base[8]))
        # rot 180
        variants.add(GiftPattern(
            self.base[6] + self.base[7] + self.base[8] +
            self.base[3] + self.base[4] + self.base[5] +
            self.base[0] + self.base[1] + self.base[2]))
        # rot 270
        variants.add(GiftPattern(
            self.base[8] + self.base[5] + self.base[2] +
            self.base[7] + self.base[4] + self.base[1] +
            self.base[6] + self.base[3] + self.base[0]))

        return variants


    @cached_property
    def variants??(self) -> set["GiftPattern"]:
        variants = set()
        variants.add(self)
        # vertical flip
        variants.add(GiftPattern(
            self.base[2] + self.base[1] + self.base[0] +
            self.base[5] + self.base[4] + self.base[3] +
            self.base[8] + self.base[7] + self.base[6]))
        # horizontal flip
        variants.add(GiftPattern(
            self.base[6] + self.base[7] + self.base[8] +
            self.base[3] + self.base[4] + self.base[5] +
            self.base[0] + self.base[1] + self.base[2]))
        # rot 90
        variants.add(GiftPattern(
            self.base[6] + self.base[3] + self.base[0] +
            self.base[7] + self.base[4] + self.base[1] +
            self.base[8] + self.base[5] + self.base[2]))
        # rot 180
        variants.add(GiftPattern(
            self.base[8] + self.base[7] + self.base[6] +
            self.base[5] + self.base[4] + self.base[3] +
            self.base[2] + self.base[1] + self.base[0]))
        # rot 270
        variants.add(GiftPattern(
            self.base[2] + self.base[5] + self.base[8] +
            self.base[1] + self.base[4] + self.base[7] +
            self.base[0] + self.base[3] + self.base[6]))


        return variants

    def does_match(self, pattern: str) -> bool:
        for i, p in enumerate(pattern):
            if p != '.' and self.base[i] == '#':
                return False
        return True



    def __str__(self):
        return self.base[:3] + "\n" + self.base[3:6] + "\n" + self.base[6:] + "\n"


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    2
    """
    total = 0

    gift_patterns: list[str] = []
    gift_pattern: str = ""
    for line in lines:
        if line and line[0] == '/':
            continue

        if re.match("[#.]{3}", line):
            gift_pattern += line
        elif len(line) == 0:
            gift_patterns.append(gift_pattern)
            gift_pattern = ""
        else:
            m = re.match("([0-9]+)x([0-9]+):(.*)", line)
            if m:
                gifts: list[GiftPattern] = list(map(GiftPattern, gift_patterns))

                # for gift in gifts:
                #     log.debug(f"Gift\n{gift.base}:")
                #     for variant in gift.variants:
                #         log.debug(variant)

                width = int(m.group(1))
                height = int(m.group(2))
                gifts_histo = list(map(int, m.group(3).split()))

                col = list("." * height)
                g: list[list[str]] = []
                for x in range(width):
                    g.append(col.copy())

                total += _solve_task(width, height, gifts_histo, gifts, g, 0, 0)

    return total

def _solve_task(width: int, height: int, gifts_histo: list[int], gifts: list[GiftPattern], g: list[list[str]], from_x: int, from_y: int):
    log.info(f"w={width}, h={height}, gh={gifts_histo}, from_x={from_x}, from_y={from_y}")

    # TODO JVe FIX from_x & from_y
    # TODO JVe Prune suboptimal solutions?
    #   Based on x I know how many cols I've already covered, then count how many squares were indeed set!
    #   Fist, I must use depth-first search
    # TODO JVe Look for squares?
    for x in range(from_x, width - 2):
        for y in range(0, height - 2):
            required_pattern = (g[x][y + 0] + g[x + 1][y + 0] + g[x + 2][y + 0] +
                                g[x][y + 1] + g[x + 1][y + 1] + g[x + 2][y + 1] +
                                g[x][y + 2] + g[x + 1][y + 2] + g[x + 2][y + 2])
            for i, gift_candidate in enumerate(gifts_histo):
                if gift_candidate == 0:
                    continue
                for gift_variant in gifts[i].variants:
                    if gift_variant.does_match(required_pattern):
                        log.debug(f"Match found: {gift_variant.base}")
                        random_l = random.choice(string.ascii_letters)
                        new_g =[col[:] for col in g]
                        for j, p in enumerate(gift_variant.base):
                            if p != ".":
                                new_g[x + (j % 3)][y + (j // 3)] = random_l
                        printg(new_g)

                        new_histo = gifts_histo.copy()
                        new_histo[i] -= 1

                        if sum(new_histo) == 0:
                            log.info("BINGO - Solved!")
                            return 1



                        res = _solve_task(width, height, new_histo, gifts, new_g, x, y)
                        if res:
                            return 1

                        # TODO Add into grid



    return 0


def printg(g: list[list[str]]):
    for y in range(len(g[0])):
        line = ""
        for x in range(len(g)):
            line += g[x][y]
        log.debug(line)



def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))

    """
    for line in lines:
        pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=None)
    timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=None)
