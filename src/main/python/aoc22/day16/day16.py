import logging
import pprint
import re
from dataclasses import dataclass
from typing import List, FrozenSet

from data_input import read_all_lines
from simple_logging import log


@dataclass(frozen=True)
class Valve:
    name: str
    flow_rate: int
    neighbors: List

    def __repr__(self) -> str:
        return f"{self.name}={self.flow_rate}: {map(Valve.name, self.neighbors)}"


@dataclass
class TraversalCtx(frozen=True):
    valve: Valve
    time: int
    open_valves: FrozenSet[str]
    score: int

    def __repr__(self) -> str:
        return f"{self.valve.name}: time={self.time}, score={self.score}, open_valves={self.open_valves}"


def star1(lines: List[str]):
    """
    >>> star1(read_all_lines("input-test.txt"))
    1651
    """

    valves = []
    for line in lines:
        valve_names = re.findall("([A-Z]{2})", line)
        flow_rate = int(re.findall("rate=(\d+);", line)[0])
        valve = Valve(valve_names[0], flow_rate, valve_names[1:])
        valves.append(valve)

    log.debug(pprint.pformat(valves))

    best_scores = {}

    q = [TraversalCtx(valves[0], 30, frozenset(), 0)]

    while q:
        ctx = q.pop()
        log.debug(ctx)
        valve = ctx.valve

        # TODO check best score !!!

        if valve.flow_rate > 0 and valve.name not in ctx.open_valves:
            open_valves = frozenset(ctx.open_valves.union(valve.name))
            score = ctx.score + (ctx.time - 1) * valve.flow_rate
            q.append(TraversalCtx(valve, ctx.time - 1, open_valves, score))

        for neighbor in ctx.valve.neighbors:
            q.append(TraversalCtx(neighbor, ctx.time - 1, ctx.open_valves, ctx.score))


def star2(lines: List[str]):
    """
    >>> star2(read_all_lines("input-test.txt"))
    'TODO'
    """

    pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    lines = read_all_lines("input.txt")
    print(f"Star 1: {star1(lines)}")
    print(f"Star 2: {star2(lines)}")

    # Star 1:
    # Star 2:
