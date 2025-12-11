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
    # for line in set(lines):  # TODO JVe random
    for line in lines:
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

        button_joltages.sort(key=sum)

        min_pushes: int | None = None
        max_joltage_index = joltage_desired.index(max(joltage_desired))
        queue = [ButtonPushS2(joltage, joltage_desired) for joltage in button_joltages if joltage[max_joltage_index] == 1]
        # queue = [ButtonPushS2(joltage, joltage_desired) for joltage in button_joltages]
        # queue = SortedSet()
        # _add_to_queue((0,) * len(joltage_final), button_joltages, 0, joltage_final, queue, min_pushes)
        steps = 0

        bad_joltages = set()
        while queue:
            button_push = queue.pop()
            steps += 1
            log.debug(button_push)
            # if min_pushes and button_push.counter >= min_pushes:
            #     log.debug("  skip min_pushes")
            #     continue

            remaining_joltage = tuple(map(lambda pair: pair[0] - pair[1], zip(button_push.remaining_joltage, button_push.button_joltage)))
            if any(filter(lambda j: j < 0, remaining_joltage)):
                bad_joltages.add(remaining_joltage)
                continue
            if remaining_joltage in bad_joltages:
                continue

            # for acc_j, final_j in zip(accumulated_joltage, joltage_final):
            #     if acc_j > final_j:
            #         # log.info("XXX")
            #         break

            # if accumulated_joltage not in best_options or button_push.counter < best_options[accumulated_joltage]:
            #     best_options[accumulated_joltage] = button_push.counter
            # # elif button_push.counter >= best_options[accumulated_joltage]:
            # else:
            #     log.debug(f"  skip best_options {accumulated_joltage}")
            #     continue
            # else:
            #     lower_joltage = True
            #     for mj, bj in zip(missing_joltage, button_joltage):
            #         if bj == 1:
            #             if mj < max_pushes:
            #                 max_pushes = mj
            #     continue

            if remaining_joltage == joltage_zero:
                log.info(f"  Found : {button_push.counter} (steps: {steps})")
                min_pushes = button_push.counter
                break
            else:
                max_joltage_index = max(remaining_joltage)  # focus on the biggest values
                # queue = [ButtonPushS2(joltage, remaining_joltage, button_push.counter + 1) for joltage in button_joltages if joltage[max_joltage_index] == 1]
                button_joltage_candidates1 = []
                button_joltage_candidates2 = []
                for button_joltage in button_joltages:
                    good = True
                    for i, rj in enumerate(remaining_joltage):
                        if rj == 0 and button_joltage[i] == 1:
                            good = False
                            break
                    if good:
                        button_joltage_candidates2.append(button_joltage)
                        good = False
                        for i, rj in enumerate(remaining_joltage):
                            if rj == max_joltage_index and button_joltage[i] == 1:
                                good = True
                                break
                        if good:
                            button_joltage_candidates1.append(button_joltage)

                button_joltage_candidates = []
                if button_joltage_candidates1:
                    button_joltage_candidates = button_joltage_candidates1
                elif button_joltage_candidates2:
                    button_joltage_candidates = button_joltage_candidates2





                queue.extend([ButtonPushS2(joltage, remaining_joltage, button_push.counter + 1) for joltage in button_joltage_candidates])

        # _add_to_queue(accumulated_joltage, button_joltages, button_push.counter, joltage_final, queue,
        #                           min_pushes)

        total += min_pushes

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
    log.setLevel(logging.DEBUG)
    # timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=547)
    # timed_run("Star 2", lambda: star2(read_input(__file__, input_file="input4.txt")), expected_result=None)
    timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=None)
