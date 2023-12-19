import dataclasses
import logging
import re
from typing import Dict, List, Optional

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


@dataclasses.dataclass(frozen=True)
class Filter:
    rating: str
    operator: str
    value: int


@dataclasses.dataclass(frozen=True)
class Condition:
    filter: Optional[Filter]
    action: str


@dataclasses.dataclass(frozen=True)
class Workflow:
    id: str
    conditions: list[Condition] = dataclasses.field(default_factory=list)


PART = Dict[str, int]


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    19114
    """

    workflows: Dict[str, Workflow] = {}
    parts: List[PART] = []

    for line in lines:
        if line:
            if line.startswith("{"):
                parts.append(parse_part(line))
            else:
                workflow = parse_workflow(line)
                workflows[workflow.id] = workflow

    log.debug(workflows)
    log.debug(parts)


def parse_workflow(line) -> Workflow:
    wid, conditions = re.findall(r"([a-z]+)\{(.*)}", line)[0]
    workflow = Workflow(wid)
    for condition in conditions.split(","):
        if ":" in condition:
            filter_str, action = condition.split(":")
            cond_filter = Filter(filter_str[0], filter_str[1], int(filter_str[2:]))
        else:
            cond_filter = None
            action = condition
        workflow.conditions.append(Condition(cond_filter, action))
    return workflow


def parse_part(line) -> PART:
    part = {}
    for rating in line[1:-1].split(","):
        k, v = rating.split("=")
        part[k] = int(v)
    return part


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))

    """
    for line in lines:
        pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1:
    # Star 2:
