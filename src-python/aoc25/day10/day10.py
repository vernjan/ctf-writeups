import dataclasses
import logging
import re
from functools import reduce

from scipy.optimize import linprog

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


@dataclasses.dataclass
class ButtonPush:
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
        queue = [ButtonPush(mask) for mask in button_masks]
        while queue:
            button_push = queue.pop(0)
            if min_pushes and button_push.counter >= min_pushes:
                continue

            lights = button_push.lights ^ button_push.button_mask

            if lights not in best_options:  # TODO JVe Never updated ..
                best_options[lights] = button_push.counter
            elif button_push.counter >= best_options[lights]:
                continue

            if lights_final == lights:
                log.debug(f"  Found new best: {button_push.counter}")
                min_pushes = button_push.counter
            else:
                queue.extend(
                    [ButtonPush(mask, lights, button_push.counter + 1) for mask in button_masks if
                     mask != button_push.button_mask])

        total += min_pushes

    return total


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    33
    """

    total = 0
    for line in lines:
        joltage_str: str = re.findall("\\{([0-9,]+)}", line)[0]
        joltage_target = tuple(map(int, joltage_str.split(",")))
        buttons = [list(map(int, button.split(","))) for button in re.findall("\\(([0-9,]+)\\)", line)]

        log.debug(f"Solving {joltage_str}: {buttons}")

        # Example: (3) (1,3) (2) (2,3) (0,2) (0,1) {3,5,4,7}
        # Solve using linear programming:
        #   objective_function: min z =  a + b + c + d + e + f
        #     - `a` represents how many times we pushed the first button, `b` the second button and so on
        #     - coefficients are always 1 - each button push has the same cost
        #   constraints:
        #     e + f = 3
        #     b + f = 5
        #     c + d + e = 4
        #     a + b + d = 7

        obj = [1] * len(buttons)  # objective function coefficients (always 1s)

        # constraints left-hand side
        lhs_eq = []
        for i in range(len(joltage_target)):
            constraints = []
            for button in buttons:
                constraints.append(1 if i in button else 0)
            lhs_eq.append(constraints)

        # constraints right-hand side
        rhs_eq = joltage_target

        # solve
        opt = linprog(c=obj, A_eq=lhs_eq, b_eq=rhs_eq, integrality=obj)  # set integrality for all coefficients to force mixed-integer LP (MILP)
        log.debug(f"  Solved: {int(opt.fun)}")
        total += int(opt.fun)

    return total


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=547)
    timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=21111)
