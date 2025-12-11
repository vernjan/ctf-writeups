import dataclasses
import logging
import re
from functools import reduce

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

            if lights not in best_options:  # TODO JVe Never updated ..
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
    remaining_joltage: tuple[int, ...]
    # available_buttons: list[tuple[int, ...]]
    counter: int = 1

    # def __lt__(self, other):
    #     my_joltage = sum(self.remaining_joltage) // self.counter
    #     other_joltage = sum(other.remaining_joltage) // other.counter
    #     if my_joltage != other_joltage:
    #         return my_joltage < other_joltage
    #     return sum(self.button_joltage) < sum(other.button_joltage)


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    33
    """
    total = 0
    for line in set(lines):  # TODO JVe random
        # for line in lines:
        #     best_options: dict[tuple[int, ...], int] = {}  # accumulated joltage: number of pushes
        # best_options2: dict[int, set[tuple[int, ...]]] = {}  # accumulated joltage: number of pushes

        joltage_str: str = re.findall("\\{([0-9,]+)}", line)[0]
        joltage_desired = tuple(map(int, joltage_str.split(",")))
        joltage_zero = (0,) * len(joltage_desired)

        log.info(f"Solving {joltage_str}")

        buttons = [list(map(int, button.split(","))) for button in re.findall("\\(([0-9,]+)\\)", line)]
        button_joltages = []
        for button in buttons:
            button_joltage = [0] * len(joltage_desired)
            for i in button:
                button_joltage[i] = 1
            button_joltages.append(tuple(button_joltage))

        # all = reduce(lambda a, b: tuple(map(sum, zip(a, b))), button_joltages)
        # log.debug(all)

        button_joltages.sort(key=sum, reverse=True)  # be greedy

        bad_joltages = set()

        def solve(button_joltage: tuple, remaining_joltage: tuple, steps: int) -> tuple[bool, int]:
            remaining_joltage = tuple(map(lambda pair: pair[0] - pair[1], zip(remaining_joltage, button_joltage)))

            log.debug(f"bj={button_joltage}, rj={remaining_joltage}, steps={steps}")

            if remaining_joltage in bad_joltages:
                log.debug(f"Bad joltage: {remaining_joltage}")
                return False, 0

            if any(filter(lambda j: j < 0, remaining_joltage)):
                bad_joltages.add(remaining_joltage)
                return False, 1

            if remaining_joltage == joltage_zero:
                return True, steps

            min_joltage_index = min(filter(lambda x: x > 0, remaining_joltage))
            min_indexes = []
            for i, rj in enumerate(remaining_joltage):
                if rj == min_joltage_index:
                    min_indexes.append(i)

            button_joltage_candidates = []
            for button_joltage in button_joltages:
                for mi in min_indexes:
                    if button_joltage[mi] == 1:
                        button_joltage_candidates.append(button_joltage)
                        break
                # if button_joltage[min_joltage_index] == 1:
                #     # good = True
                #     # for i, rj in enumerate(remaining_joltage):
                #     #     if rj == 0 and button_joltage[i] == 1:
                #     #         good = False
                #     #         break
                #     # if good:
                #     button_joltage_candidates.append(button_joltage)

            for button_joltage in button_joltage_candidates:
                if remaining_joltage in bad_joltages:
                    return False, 0
                res, s = solve(button_joltage, remaining_joltage, steps + 1)
                if res:
                    return True, s
            bad_joltages.add(remaining_joltage)
            return False, 0

        min_joltage_index = joltage_desired.index(min(filter(lambda x: x > 0, joltage_desired)))
        for button_joltage in [bj for bj in button_joltages if bj[min_joltage_index] == 1]:
            # for button_joltage in button_joltages:
            res, min_pushes = solve(button_joltage, joltage_desired, 1)
            if res:
                log.info(f"  Found: (steps: {min_pushes})")
                total += min_pushes
                break

    return total


# def _add_to_queue(accumulated_joltage, button_joltages, counter, joltage_final, queue: SortedSet, best_so_far):
def _add_to_queue(accumulated_joltage, button_joltages, counter, joltage_final, queue: list, best_so_far):
    missing_joltage = tuple(map(lambda pair: pair[0] - pair[1], zip(joltage_final, accumulated_joltage)))

    for button_joltage in button_joltages:
        max_pushes = 1000
        for mj, bj in zip(missing_joltage, button_joltage):
            if bj == 1:
                if mj < max_pushes:
                    max_pushes = mj
        queue.extend(
            [ButtonPushS2(tuple(map(lambda j: j * i, button_joltage)), accumulated_joltage,
                          counter + i) for i in
             filter(lambda p: max_pushes >= p >= max_pushes / 2 and counter + p < best_so_far, reversed(PRIMES))])


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    # timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=547)
    # timed_run("Star 2", lambda: star2(read_input(__file__, input_file="input1.txt")), expected_result=None)
    # timed_run("Star 2", lambda: star2(read_input(__file__, input_file="input2.txt")), expected_result=None)
    # timed_run("Star 2", lambda: star2(read_input(__file__, input_file="input3.txt")), expected_result=None)
    timed_run("Star 2", lambda: star2(read_input(__file__, input_file="input4.txt")), expected_result=None)
    # timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=None)
