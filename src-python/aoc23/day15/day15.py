import logging
from collections import defaultdict
from functools import reduce

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    1320
    """
    return sum(map(_hash, lines[0].split(",")))


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    145
    """
    boxes = defaultdict(dict)  # Python preserves insertion order in dicts
    for step in lines[0].split(","):
        if "=" in step:
            label, focal_length = step.split("=")
            boxes[_hash(label)][label] = int(focal_length)
        elif "-" in step:
            label = step[:-1]
            box_hash = _hash(label)
            if label in boxes[box_hash]:
                del boxes[box_hash][label]

    focus_power = 0
    for box_hash in range(256):
        box = boxes[box_hash]
        for slot, (label, focal_length) in enumerate(box.items()):
            focus_power += (box_hash + 1) * (slot + 1) * focal_length
    return focus_power


def _hash(input: str):
    """
    >>> _hash("HASH")
    52
    """
    return reduce(lambda x, y: ((x + ord(y)) * 17) % 256, input, 0)


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 510388
    # Star 2: 291774
