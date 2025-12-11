import dataclasses
import logging
import re
from functools import reduce

from sortedcontainers import SortedSet

from util.data_io import read_input, read_test_input, timed_run
from util.log import log

PRIMES = [1, 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103,
          107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199]


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

            if lights not in best_options: # TODO JVe Never updated ..
                best_options[lights] = button_push.counter
            elif button_push.counter >= best_options[lights]:
                continue

            if lights_final == lights:
                log.debug(f"  Found new best: {button_push.counter}")
                min_pushes = button_push.counter
            else:
                queue.extend(
                    [ButtonPushS1(mask, lights, button_push.counter + 1) for mask in button_masks if
                     mask != button_push.button_mask])

        total += min_pushes

    return total


@dataclasses.dataclass(frozen=True)
class ButtonPushS2:
    button_joltage: tuple[int, ...]
    accumulated_joltage: tuple[int, ...]
    counter: int = 1

    def __lt__(self, other):
        my_joltage = sum(self.accumulated_joltage) // self.counter
        other_joltage = sum(other.accumulated_joltage) // other.counter
        if my_joltage != other_joltage:
            return my_joltage < other_joltage
        return sum(self.button_joltage) < sum(other.button_joltage)


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    33
    """
    total = 0
    for line in lines:  # TODO JVe random
    # for line in lines:
        best_options: dict[tuple[int, ...], int] = {}  # accumulated joltage: number of pushes
        # best_options2: dict[int, set[tuple[int, ...]]] = {}  # accumulated joltage: number of pushes


        joltage_str: str = re.findall("\\{([0-9,]+)}", line)[0]
        joltage_final = tuple(map(int, joltage_str.split(",")))

        log.info(f"Solving {joltage_str}")

        buttons = [list(map(int, button.split(","))) for button in re.findall("\\(([0-9,]+)\\)", line)]
        button_joltages = []
        for button in buttons:
            button_joltage = [0] * len(joltage_final)
            for i in button:
                button_joltage[i] = 1
            button_joltages.append(tuple(button_joltage))

        # all = reduce(lambda a, b: tuple(map(sum, zip(a, b))), button_joltages)
        # log.debug(all)

        button_joltages.sort(key=sum)

        min_pushes: int | None = 10000
        # queue = [ButtonPushS2(joltage, (0,) * len(joltage)) for joltage in button_joltages]
        queue = SortedSet()
        _add_to_queue((0,) * len(joltage_final), button_joltages, 0, joltage_final, queue, min_pushes)
        while queue:
            button_push = queue.pop()
            log.debug(button_push)
            if min_pushes and button_push.counter >= min_pushes:
                log.debug("  skip min_pushes")
                continue

            accumulated_joltage = tuple(map(sum, zip(button_push.accumulated_joltage, button_push.button_joltage)))

            # for acc_j, final_j in zip(accumulated_joltage, joltage_final):
            #     if acc_j > final_j:
            #         # log.info("XXX")
            #         break

            if accumulated_joltage not in best_options or button_push.counter < best_options[accumulated_joltage]:
                best_options[accumulated_joltage] = button_push.counter
            # elif button_push.counter >= best_options[accumulated_joltage]:
            else:
                log.debug(f"  skip best_options {accumulated_joltage}")
                continue
            # else:
            #     lower_joltage = True
            #     for mj, bj in zip(missing_joltage, button_joltage):
            #         if bj == 1:
            #             if mj < max_pushes:
            #                 max_pushes = mj
            #     continue

            if joltage_final == accumulated_joltage:
                log.info(f"  Found new best: {button_push.counter}, qs: {len(queue)}" )
                min_pushes = button_push.counter
            else:
                _add_to_queue(accumulated_joltage, button_joltages, button_push.counter, joltage_final, queue,
                              min_pushes)

        total += min_pushes

    return total


def _add_to_queue(accumulated_joltage, button_joltages, counter, joltage_final, queue: SortedSet, best_so_far):
    missing_joltage = tuple(map(lambda pair: pair[0] - pair[1], zip(joltage_final, accumulated_joltage)))

    for button_joltage in button_joltages:
        max_pushes = 1000
        for mj, bj in zip(missing_joltage, button_joltage):
            if bj == 1:
                if mj < max_pushes:
                    max_pushes = mj
        queue.update(
            [ButtonPushS2(tuple(map(lambda j: j * i, button_joltage)), accumulated_joltage,
                          counter + i) for i in
             filter(lambda p: max_pushes >= p >= max_pushes / 2 and counter + p < best_so_far, reversed(PRIMES))])


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    # timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=547)
    # timed_run("Star 2", lambda: star2(read_input(__file__, input_file="input4.txt")), expected_result=None)
    timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=None)
