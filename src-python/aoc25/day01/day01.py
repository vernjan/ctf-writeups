import logging

from util.data_io import read_input, timed_run, read_test_input
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    3
    """
    pos = 50
    zero_counter = 0

    for line in lines:
        lr = line[0]
        steps = int(line[1:]) % 100
        if lr == 'L':
            pos = pos - steps
            if pos < 0:
                pos = pos + 100
        else:
            pos = pos + steps
            if pos > 99:
                pos = pos - 100

        if pos == 0:
            zero_counter = zero_counter + 1

    return zero_counter


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    6
    """
    pos = 50
    zero_counter = 0

    for line in lines:
        lr = line[0]
        steps = int(line[1:])
        extra_steps = steps // 100
        steps = steps % 100
        if lr == 'L':
            if pos == 0:  # dont count 0 twice
                pos = 100 - steps
            else:
                pos = pos - steps
                if pos <= 0:
                    zero_counter = zero_counter + 1
                if pos < 0:
                    pos = pos + 100
        else:
            pos = pos + steps
            if pos > 99:
                zero_counter = zero_counter + 1
                pos = pos - 100

        zero_counter = zero_counter + extra_steps

    return zero_counter


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 1074
    # Star 2: 6254
