import logging
import math
import re
from typing import List, Dict, Set

from util.data_io import read_input, read_test_input, timed_run
from util.log import log

ORE = "ore"
CLAY = "clay"
OBSIDIAN = "obsidian"
GEODE = "geode"

RESOURCE_TYPES = [GEODE, OBSIDIAN, CLAY, ORE]


class Blueprint:

    def __init__(self, bp_id,
                 ore_robot_cost,
                 clay_robot_cost,
                 obsidian_robot_cost_ore,
                 obsidian_robot_cost_clay,
                 geode_robot_cost_ore,
                 geode_robot_cost_obsidian,
                 ) -> None:
        self.id = bp_id
        self.robot_costs: Dict[str, Dict[str, int]] = {
            ORE: {
                ORE: ore_robot_cost
            },
            CLAY: {
                ORE: clay_robot_cost
            },
            OBSIDIAN: {
                ORE: obsidian_robot_cost_ore,
                CLAY: obsidian_robot_cost_clay
            },
            GEODE: {
                ORE: geode_robot_cost_ore,
                OBSIDIAN: geode_robot_cost_obsidian
            }
        }
        self.max_robot_costs = {
            ORE: max([ore_robot_cost, clay_robot_cost, obsidian_robot_cost_ore, geode_robot_cost_ore]) - 1,
            CLAY: 4,
            OBSIDIAN: 4,
            GEODE: math.inf
        }

    def __repr__(self) -> str:
        return f"Blueprint {self.id}: {self.robot_costs}"


class Stash:
    def __init__(self, resources: Dict[str, int], robots: Dict[str, int]) -> None:
        self.resources = resources
        self.robots = robots

    @staticmethod
    def empty():
        resources = {}
        robots = {}
        for rt in RESOURCE_TYPES:
            resources[rt] = 0
            robots[rt] = 0
        robots[ORE] = 1
        return Stash(resources, robots)

    def can_build_robot(self, bp: Blueprint, robot_resource_type: str) -> bool:
        robot_costs = bp.robot_costs[robot_resource_type]
        for rt, cost in robot_costs.items():
            if self.resources[rt] < cost:
                return False
        return True

    def collect(self) -> "Stash":
        new_resources = {}
        for rt in RESOURCE_TYPES:
            new_resources[rt] = self.resources[rt] + self.robots[rt]
        return Stash(new_resources, dict(self.robots))

    def build_and_collect(self, bp: Blueprint, robot_resource_type: str) -> "Stash":
        new_resources = dict(self.resources)
        new_robots = dict(self.robots)

        # build
        robot_costs = bp.robot_costs[robot_resource_type]
        for rt, cost in robot_costs.items():
            new_resources[rt] -= cost
        new_robots[robot_resource_type] += 1

        # collect
        for rt in RESOURCE_TYPES:
            new_resources[rt] += self.robots[rt]

        return Stash(new_resources, new_robots)

    def __repr__(self) -> str:
        return f"Stash\n  resources: {self.resources}\n  robots: {self.robots}"

    def __hash__(self) -> int:
        return hash(tuple(self.resources.values()) + tuple(self.robots.values()))


def star1(lines: List[str]):
    """
    >>> star1(read_test_input(__file__))
    33
    """

    log.setLevel(logging.WARN)

    total_quality = 0
    for bp in _parse_blueprints(lines):
        bp_quality = _evaluate_blueprint(bp, Stash.empty(), 1, {})
        total_quality += bp.id * bp_quality
        log.warn(f"Blueprint {bp.id} evaluated: {bp_quality}")

    return total_quality


def star2(lines: List[str]):
    """
    >>> star2(read_test_input(__file__))

    """

    pass


def _parse_blueprints(lines: List[str]) -> List[Blueprint]:
    blueprints = []
    for bp in lines:
        bp_data = list(map(int, re.findall("[0-9]+", bp)))
        assert len(bp_data) == 7
        blueprints.append(Blueprint(*bp_data))
    log.debug(blueprints)
    return blueprints


def _evaluate_blueprint(bp: Blueprint, stash: Stash, time: int, mem: Dict[int, Set[int]]) -> int:
    if time > 24:
        if stash.resources[GEODE] > 8:
            log.info(f"Blueprint variation {bp.id} finished: {stash}")
        return stash.resources[GEODE]

    if time not in mem:
        mem[time] = set()
    if stash in mem[time]:
        return 0
    # mem[time].add(hash(stash))
    mem[time].add(stash)

    log.debug(f"Time {time}: {stash}")
    max_geodes = 0
    try_collecting = True
    for rt in RESOURCE_TYPES:
        if stash.robots[rt] < bp.max_robot_costs[rt] and stash.can_build_robot(bp, rt):
            geodes = _evaluate_blueprint(bp, stash.build_and_collect(bp, rt), time + 1, mem)
            if geodes > max_geodes:
                max_geodes = geodes
            if rt == GEODE:
                try_collecting = False
                continue
            if rt == OBSIDIAN:
                continue

    if try_collecting:
        geodes = _evaluate_blueprint(bp, stash.collect(), time + 1, mem)
        if geodes > max_geodes:
            max_geodes = geodes

    return max_geodes


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1:
    # Star 2:
