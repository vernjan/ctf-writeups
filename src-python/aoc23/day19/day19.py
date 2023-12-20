import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


@dataclass(frozen=True)
class Filter:
    rating: str
    operator: str
    value: int

    def invert(self):
        inverted_operator, inverted_value = (">", self.value - 1) if self.operator == "<" else ("<", self.value + 1)
        return Filter(self.rating, inverted_operator, inverted_value)

    def __repr__(self):
        return f"{self.rating}{self.operator}{self.value}"


@dataclass(frozen=True)
class Condition:
    filter: Optional[Filter]
    action: str


@dataclass(frozen=True)
class Workflow:
    id: str
    conditions: list[Condition] = field(default_factory=list)


A_ID = Tuple[str, int]  # workflow_id, condition_index
PART = Dict[str, int]

MIN_RATING = 0
MAX_RATING = 4001


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    19114
    """
    workflows, parts = _parse_input(lines)
    accept_filters = calc_accept_filters(workflows)

    def is_part_approved(part, accept_filter):
        for rating, (rating_min, rating_max) in accept_filter.items():
            if not rating_min < part[rating] < rating_max:
                return False
        return True

    total = 0
    for part in parts:
        for accept_filter in accept_filters:
            if is_part_approved(part, accept_filter):
                total += sum(part.values())
                break
    return total


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    167409079868000
    """
    workflows, parts = _parse_input(lines)
    accept_filters = calc_accept_filters(workflows)

    total = 0
    for accept_filter in accept_filters:
        subtotal = 1
        for rating_min, rating_max in accept_filter.values():
            subtotal *= (rating_max - rating_min - 1)
        for i in range(4 - len(accept_filter)):
            subtotal *= 4000
        total += subtotal
    return total


def _parse_input(lines) -> Tuple[Dict[str, Workflow], List[PART]]:
    def parse_workflow():
        workflow_id, conditions = re.findall(r"([a-z]+)\{(.*)}", line)[0]
        workflow = Workflow(workflow_id)
        for condition in conditions.split(","):
            if ":" in condition:
                filter_str, action = condition.split(":")
                cond_filter = Filter(filter_str[0], filter_str[1], int(filter_str[2:]))
            else:
                cond_filter = None
                action = condition
            workflow.conditions.append(Condition(cond_filter, action))
        return workflow

    def parse_part():
        part = {}
        for rating_value in line[1:-1].split(","):
            rating, value = rating_value.split("=")
            part[rating] = int(value)
        return part

    workflows: Dict[str, Workflow] = {}
    parts: List[PART] = []
    for line in lines:
        if line:
            if line.startswith("{"):
                parts.append(parse_part())
            else:
                workflow = parse_workflow()
                workflows[workflow.id] = workflow

    return workflows, parts


def calc_accept_filters(workflows) -> List[Dict[str, Tuple[int, int]]]:
    reverse_workflows: Dict[str, A_ID] = defaultdict()
    for workflow in workflows.values():
        for i, condition in enumerate(workflow.conditions):
            if condition.action not in "RA":
                reverse_workflows[condition.action] = (workflow.id, i)

    def collect_accept_filters(
            workflow: Workflow,
            condition_index: int,
            collect_filters=False,
            invert_filters=True) -> List[Filter]:
        filters = []
        for i in range(condition_index, -1, -1):
            condition = workflow.conditions[i]
            cond_filter = condition.filter
            if collect_filters and cond_filter:
                filters.append(cond_filter.invert() if invert_filters else cond_filter)
            invert_filters = True
            if condition.action == "A":
                a_key = workflow.id, i
                if a_key not in accept_filters_dict:
                    log.debug(f"Starting reverse search for {a_key}")
                    a_filters = collect_accept_filters(workflow, i - 1, collect_filters=True)
                    if cond_filter:
                        a_filters.insert(0, cond_filter)
                    accept_filters_dict[a_key] = a_filters
                    log.debug(f"Reverse search finished for {a_key}: {list(reversed(a_filters))}")

        prev_workflow = reverse_workflows.get(workflow.id)
        if prev_workflow:
            prev_workflow_id, prev_workflow_index = prev_workflow
            filters += collect_accept_filters(workflows[prev_workflow_id],
                                              prev_workflow_index,
                                              collect_filters=collect_filters,
                                              invert_filters=False)

        return filters

    accept_filters_dict: Dict[A_ID, List[Filter]] = {}
    for workflow in workflows.values():
        collect_accept_filters(workflow, len(workflow.conditions) - 1)

    squashed_accept_filters = []
    for accept_filter_list in accept_filters_dict.values():
        squashed_filter: Dict[str, Tuple[int, int]] = {}
        for af in accept_filter_list:
            rating_min, rating_max = squashed_filter.get(af.rating, (MIN_RATING, MAX_RATING))
            if af.operator == ">":
                squashed_filter[af.rating] = (max(rating_min, af.value), rating_max)
            else:
                squashed_filter[af.rating] = (rating_min, min(rating_max, af.value))
        squashed_accept_filters.append(squashed_filter)
        log.debug(f"Accept filter list: {accept_filter_list} -> {squashed_filter}")
    return squashed_accept_filters


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 367602
    # Star 2: 125317461667458
