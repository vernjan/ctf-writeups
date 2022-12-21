import logging
import math
import re
from typing import List, Dict, Tuple

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
            ORE: max([ore_robot_cost, clay_robot_cost, obsidian_robot_cost_ore, geode_robot_cost_ore]),
            CLAY: obsidian_robot_cost_clay,
            OBSIDIAN: geode_robot_cost_obsidian,
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
        return f"Stash resources: {self.resources}, robots: {self.robots}"

    def __hash__(self) -> int:
        return hash(tuple(self.resources.values()) + tuple(self.robots.values()))


def star1(lines: List[str]):
    """
    >>> star1(read_test_input(__file__))
    33
    """

    total = 0
    for bp in _parse_blueprints(lines):
        bp_quality, steps = _evaluate_blueprint(bp, 24)
        total += bp.id * bp_quality
        log.debug(f"Blueprint {bp.id} evaluated: {bp_quality} in {steps} steps")

    return total


def star2(lines: List[str]):
    """
    >>> star2(read_test_input(__file__))
    3472
    """

    total = 1
    for bp in _parse_blueprints(lines[:3]):
        bp_quality, steps = _evaluate_blueprint(bp, 32)
        total *= bp_quality
        log.debug(f"Blueprint {bp.id} evaluated: {bp_quality} in {steps} steps")

    return total


def _parse_blueprints(lines: List[str]) -> List[Blueprint]:
    blueprints = []
    for bp in lines:
        bp_data = list(map(int, re.findall("[0-9]+", bp)))
        assert len(bp_data) == 7
        blueprints.append(Blueprint(*bp_data))
    log.debug(blueprints)
    return blueprints


def _evaluate_blueprint(bp: Blueprint, max_time: int) -> Tuple[int, int]:
    max_geodes = 0
    steps = 0
    mem_robots: Dict[int, Dict[Tuple, Tuple]] = {i: dict() for i in range(max_time + 1)}  # TO-DO Could use bimap
    mem_resources: Dict[int, Dict[Tuple, Tuple]] = {i: dict() for i in range(max_time + 1)}
    q = [(1, Stash.empty())]

    while q:
        time, stash = q.pop(0)

        if time > max_time:
            geodes = stash.resources[GEODE]
            if geodes > max_geodes:
                max_geodes = geodes
                log.debug(f"New max found for bp {bp.id}: {max_geodes} ({repr(stash)}")
            continue

        # Prune suboptimal states
        robots = tuple(stash.robots.values())
        resources = tuple(stash.resources.values())
        if not _update_memory(mem_robots[time], robots, resources):
            continue
        if not _update_memory(mem_resources[time], resources, robots):
            continue

        log.debug(f"Time {time}: {stash}")
        steps += 1

        collect_resources = True
        for rt in RESOURCE_TYPES:
            if stash.robots[rt] < bp.max_robot_costs[rt] and stash.can_build_robot(bp, rt):
                q.append((time + 1, stash.build_and_collect(bp, rt)))
                if rt == GEODE:
                    collect_resources = False
                    break
                if rt == OBSIDIAN:
                    collect_resources = False
                    if stash.robots[OBSIDIAN] != 0:  # Bit of magic, might need increasing for other input sets
                        break

        if collect_resources and all_values_lower_or_equal([50] * 4, stash.resources.values()):
            if stash.resources[ORE] < bp.max_robot_costs[ORE]:
                q.append((time + 1, stash.collect()))
            elif stash.robots[CLAY] and stash.resources[CLAY] < bp.max_robot_costs[CLAY]:
                q.append((time + 1, stash.collect()))
            elif stash.robots[OBSIDIAN] and stash.resources[OBSIDIAN] < bp.max_robot_costs[OBSIDIAN]:
                q.append((time + 1, stash.collect()))

    return max_geodes, steps


def _update_memory(mem, key, new_values):
    if key not in mem:
        mem[key] = new_values
        return True
    else:
        if all_values_lower_or_equal(mem[key], new_values):
            return False
        mem[key] = new_values
        return True


def all_values_lower_or_equal(base, new_values):
    for i, new_value in enumerate(new_values):
        if new_value > base[i]:
            return False
    return True


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 1349
    # Star 2: 21840
