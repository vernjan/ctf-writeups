import logging
from typing import List

from util.log import log


class Monkey:
    def __init__(self, name, items, op_fce, test_fce):
        self.name = name
        self.items = items
        self.op_fce = op_fce
        self.test_fce = test_fce
        self.total_inspects = 0

    def throw(self):
        self.total_inspects += 1
        return self.items.pop(0)

    def catch(self, item):
        self.items.append(item)


def monkeys_example():
    return [
        Monkey(0, [79, 98], lambda w: w * 19, lambda w: check_div(w, 23, 2, 3)),
        Monkey(1, [54, 65, 75, 74], lambda w: w + 6, lambda w: check_div(w, 19, 2, 0)),
        Monkey(2, [79, 60, 97], lambda w: w * w, lambda w: check_div(w, 13, 1, 3)),
        Monkey(3, [74], lambda w: w + 3, lambda w: check_div(w, 17, 0, 1)),
    ]


def monkeys():
    return [
        Monkey(0, [72, 64, 51, 57, 93, 97, 68], lambda w: w * 19, lambda w: check_div(w, 17, 4, 7)),
        Monkey(1, [62], lambda w: w * 11, lambda w: check_div(w, 3, 3, 2)),
        Monkey(2, [57, 94, 69, 79, 72], lambda w: w + 6, lambda w: check_div(w, 19, 0, 4)),
        Monkey(3, [80, 64, 92, 93, 64, 56], lambda w: w + 5, lambda w: check_div(w, 7, 2, 0)),
        Monkey(4, [70, 88, 95, 99, 78, 72, 65, 94], lambda w: w + 7, lambda w: check_div(w, 2, 7, 5)),
        Monkey(5, [57, 95, 81, 61], lambda w: w * w, lambda w: check_div(w, 5, 1, 6)),
        Monkey(6, [79, 99], lambda w: w + 2, lambda w: check_div(w, 11, 3, 1)),
        Monkey(7, [68, 98, 62], lambda w: w + 3, lambda w: check_div(w, 13, 5, 6)),
    ]


def check_div(worry, divisor, success, failure):
    return success if worry % divisor == 0 else failure


# For star 2 to keep the worries low
magic_number = 2 * 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23


def star1(lines: List[Monkey]):
    """
    >>> star1(monkeys_example())
    10605
    """

    return monkey_show(lines, rounds=20, relief_divisor=3)


def star2(lines: List[Monkey]):
    """
    >>> star2(monkeys_example())
    2713310158
    """

    return monkey_show(lines, rounds=10_000, relief_divisor=1)


def monkey_show(monkeys, rounds, relief_divisor):
    for _round in (range(rounds)):
        log.debug(f"Round: {_round}")
        for monkey in monkeys:
            log.debug(f"Monkey: {monkey.name}")
            while monkey.items:
                item = monkey.throw()
                worry = (monkey.op_fce(item) // relief_divisor) % magic_number
                next_monkey = monkey.test_fce(worry)
                monkeys[next_monkey].catch(worry)
                log.debug(f"Worry: {worry}, passing to: {next_monkey}")

    monkeys.sort(key=lambda monkey: monkey.total_inspects, reverse=True)
    return monkeys[0].total_inspects * monkeys[1].total_inspects


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    print(f"Star 1: {star1(monkeys())}")
    print(f"Star 2: {star2(monkeys())}")

    # Star 1: 99852
    # Star 2: 25935263541
