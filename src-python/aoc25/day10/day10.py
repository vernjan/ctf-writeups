import dataclasses
import logging
import re
from functools import reduce

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


@dataclasses.dataclass
class ButtonPushS1:
    button_mask: int
    lights: int = 0  # all off
    counter: int = 1


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    7
    """
    total = 0
    for line in lines:
        best_options: dict[int, int] = {}  # lights: number of steps

        lights_str: str = re.findall("\\[([.#]+)]", line)[0][::-1]
        lights_final = int(lights_str.replace(".", "0").replace("#", "1"), 2)
        buttons = [list(map(int, button.split(","))) for button in re.findall("\\(([0-9,]+)\\)", line)]
        button_masks = set(reduce(lambda a, b: a + 2 ** b, button, 0) for button in buttons)

        log.debug(f"Solving {lights_str}")

        min_pushes: int | None = None
        queue = [ButtonPushS1(mask) for mask in button_masks]
        while queue:
            button_push = queue.pop(0)
            if min_pushes and button_push.counter >= min_pushes:
                continue

            lights = button_push.lights ^ button_push.button_mask

            if lights not in best_options:
                best_options[lights] = button_push.counter
            elif button_push.counter >= best_options[lights]:
                continue

            if lights_final == lights:
                log.debug(f"  Found new best: {button_push.counter}")
                min_pushes = button_push.counter
            else:
                queue.extend(
                    [ButtonPushS1(mask, lights, button_push.counter + 1) for mask in button_masks if mask != button_push.button_mask])

        total += min_pushes

    return total


@dataclasses.dataclass
class ButtonPushS2:
    button_joltage: tuple[int, ...]
    accumulated_joltage: tuple[int, ...]
    counter: int = 1


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    33
    """
    total = 0
    for line in lines:
        best_options: dict[tuple[int, ...], int] = {}  # accumulated joltage: number of pushes

        joltage_str: str = re.findall("\\{([0-9,]+)}", line)[0]
        joltage_final = tuple(map(int, joltage_str.split(",")))

        log.debug(f"Solving {joltage_str}")

        buttons = [list(map(int, button.split(","))) for button in re.findall("\\(([0-9,]+)\\)", line)]
        button_joltages = []
        for button in buttons:
            button_joltage = [0] * len(joltage_final)
            for i in button:
                button_joltage[i] = 1
            button_joltages.append(tuple(button_joltage))

        min_pushes: int | None = None
        queue = [ButtonPushS2(joltage, (0,) * len(joltage)) for joltage in button_joltages]
        while queue:
            button_push = queue.pop(0)
            if min_pushes and button_push.counter >= min_pushes:
                continue

            accumulated_joltage = tuple(map(sum, zip(button_push.accumulated_joltage, button_push.button_joltage)))

            if accumulated_joltage not in best_options:
                best_options[accumulated_joltage] = button_push.counter
            elif button_push.counter >= best_options[accumulated_joltage]:
                continue

            if joltage_final == accumulated_joltage:
                log.debug(f"  Found new best: {button_push.counter}")
                min_pushes = button_push.counter
            else:
                queue.extend(
                    [ButtonPushS2(joltage, accumulated_joltage, button_push.counter + 1) for joltage in button_joltages if
                     joltage != button_push.button_joltage])

        total += min_pushes

    return total


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=547)
    timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=None)
