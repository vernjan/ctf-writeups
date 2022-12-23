import logging
import pprint
import re
import time
from dataclasses import dataclass
from typing import List, FrozenSet

from sortedcollections import NearestDict

from util.data_io import read_input, read_test_input
from util.log import log


@dataclass(frozen=True)
class Valve:
    name: str
    flow_rate: int
    neighbor_names: List


@dataclass(frozen=True)
class TraversalCtx:
    valve: Valve
    time: int
    open_valves: FrozenSet[str]
    score: int

    def __repr__(self) -> str:
        return f"{self.valve.name}: time={self.time}, score={self.score}, open_valves={self.open_valves}"


@dataclass(frozen=True)
class TraversalCtx2:
    valve1: Valve
    valve2: Valve
    time: int
    open_valves: FrozenSet[str]
    score: int
    tracking: List

    def __repr__(self) -> str:
        return f"{self.name()}: time={self.time}, score={self.score}, open_valves={self.open_valves}, tracking={self.tracking}"

    def name(self):
        return self.valve1.name + self.valve2.name


def star1(lines: List[str]):
    """
    >>> star1(read_test_input(__file__))
    1651
    """

    best_scores = {}
    valves = _parse_input(lines)

    q = [TraversalCtx(valves["AA"], 30, frozenset(), 0)]

    while q:
        ctx = q.pop(0)
        log.debug(ctx)
        valve = ctx.valve

        if ctx.time == 0:
            continue

        if valve.name not in best_scores:
            best_scores[valve.name] = NearestDict({ctx.time: ctx.score})
        else:
            valve_scores = best_scores[valve.name]
            score_time = valve_scores.nearest_key(ctx.time)
            best_score = valve_scores[score_time]
            if best_score > ctx.score or (best_score == ctx.score and score_time >= ctx.time):
                continue

        valve_scores = best_scores[valve.name]
        valve_scores[ctx.time] = ctx.score

        if valve.flow_rate > 0 and valve.name not in ctx.open_valves:
            open_valves = frozenset(ctx.open_valves.union([valve.name]))
            score = ctx.score + (ctx.time - 1) * valve.flow_rate
            q.append(TraversalCtx(valve, ctx.time - 1, open_valves, score))

        for neighbor in map(valves.get, ctx.valve.neighbor_names):
            q.append(TraversalCtx(neighbor, ctx.time - 1, ctx.open_valves, ctx.score))

    return _find_best_score(best_scores)


def star2(lines: List[str]):
    """
    >>> star2(read_test_input(__file__))
    1707
    """

    start = time.time()

    best_scores = {}
    valves = _parse_input(lines)

    q = [TraversalCtx2(valves["AA"], valves["AA"], 26, frozenset(), 0, [])]

    while q:
        ctx = q.pop(0)
        log.debug(ctx)
        valve1 = ctx.valve1  # me
        valve2 = ctx.valve2  # elephant

        if ctx.time == 0:
            continue

        if ctx.name() not in best_scores:
            best_scores[ctx.name()] = NearestDict({ctx.time: ctx.score})
        else:
            valve_scores = best_scores[ctx.name()]
            score_time = valve_scores.nearest_key(ctx.time)
            best_score = valve_scores[score_time]
            if best_score > ctx.score or (best_score == ctx.score and score_time >= ctx.time):
                continue

        valve_scores = best_scores[ctx.name()]
        valve_scores[ctx.time] = ctx.score

        valve1_has_open = False
        if valve1.flow_rate > 0 and valve1.name not in ctx.open_valves:
            valve1_has_open = True
            score = ctx.score + (ctx.time - 1) * valve1.flow_rate
            open_valves = frozenset(ctx.open_valves.union([valve1.name]))
            tracking = list(ctx.tracking)
            tracking.append((ctx.time - 1, valve1.name, "1"))
            for neighbor in map(valves.get, ctx.valve2.neighbor_names):
                q.append(TraversalCtx2(valve1, neighbor, ctx.time - 1, open_valves, score, tracking))

        valve2_has_open = False
        if valve2.flow_rate > 0 and valve2.name not in ctx.open_valves and valve1 != valve2:
            valve2_has_open = True
            score = ctx.score + (ctx.time - 1) * valve2.flow_rate
            open_valves = frozenset(ctx.open_valves.union([valve2.name]))
            tracking = list(ctx.tracking)
            tracking.append((ctx.time - 1, valve2.name, "2"))
            for neighbor in map(valves.get, ctx.valve1.neighbor_names):
                q.append(TraversalCtx2(neighbor, valve2, ctx.time - 1, open_valves, score, tracking))

        # both valves can be open
        if valve1_has_open and valve2_has_open:
            score = ctx.score + (ctx.time - 1) * (valve1.flow_rate + valve2.flow_rate)
            open_valves = frozenset(ctx.open_valves.union([valve1.name, valve2.name]))
            tracking = list(ctx.tracking)
            tracking.append((ctx.time - 1, valve1.name, "1"))
            tracking.append((ctx.time - 1, valve2.name, "2"))
            q.append(TraversalCtx2(valve1, valve2, ctx.time - 1, open_valves, score, tracking))

        # no valve can be open
        # (could optimize by removing the mirror moves ...)
        for neighbor1 in map(valves.get, ctx.valve1.neighbor_names):
            for neighbor2 in map(valves.get, ctx.valve2.neighbor_names):
                q.append(TraversalCtx2(neighbor1, neighbor2, ctx.time - 1, ctx.open_valves, ctx.score, ctx.tracking))

    log.info(f"Time to complete: {time.time() - start}")

    return _find_best_score(best_scores)


def _parse_input(lines):
    valves = {}
    for line in lines:
        valve_names = re.findall("([A-Z]{2})", line)
        valve_name = valve_names[0]
        flow_rate = int(re.findall("rate=(\d+);", line)[0])
        valve = Valve(valve_name, flow_rate, valve_names[1:])
        valves[valve_name] = valve
    log.debug(pprint.pformat(valves))
    return valves


def _find_best_score(best_scores):
    log.debug(best_scores)
    best_score = 0
    for valve_scores in best_scores.values():
        score = max(valve_scores.values())
        if score > best_score:
            best_score = score
    return best_score


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    lines = read_input(__file__)
    print(f"Star 1: {star1(lines)}")
    print(f"Star 2: {star2(lines)}")

    # Star 1: 2320
    # Star 2: 2967
