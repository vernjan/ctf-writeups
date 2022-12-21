import logging
from typing import List

from util.data_io import read_input, read_test_input
from util.log import log
from util.ds import Grid, Xy


def star1(instructions: List[str]):
    """
    >>> star1(read_test_input(__file__))
    13140
    """

    return _execute_instructions(instructions)[0]


def star2(instructions: List[str]):
    """
    >>> print(star2(read_test_input(__file__)))
    ##..##..##..##..##..##..##..##..##..##..
    ###...###...###...###...###...###...###.
    ####....####....####....####....####....
    #####.....#####.....#####.....#####.....
    ######......######......######......####
    #######.......#######.......#######.....

    """

    return _execute_instructions(instructions)[1]


def _execute_instructions(instr_queue: List[str]):
    sum_of_signals = 0
    crt = Grid.empty(width=40, height=6)

    reg = 1
    clock = 0
    instr_queue = instr_queue.copy()
    instr = None
    instr_cycles = None

    while instr_queue:
        log.debug(f"{clock}: x = {reg}")

        if not instr_cycles:
            instr = instr_queue.pop(0).split(" ")
            log.debug(instr)

            if instr[0] == "noop":
                instr_cycles = 1
            if instr[0] == "addx":
                instr_cycles = 2

        # Star 2:
        crt_row = clock // 40
        crt_col = clock % 40
        symbol = "#" if (reg - 1) <= crt_col <= (reg + 1) else "."
        crt.set(Xy(crt_col, crt_row), symbol)

        instr_cycles -= 1
        clock += 1

        # Star 1:
        if clock % 40 == 20:
            signal = clock * reg
            log.debug(f"Sending signal {signal} ({clock} * {reg})")
            sum_of_signals += signal

        if instr_cycles == 0:
            if instr[0] == "noop":
                pass
            if instr[0] == "addx":
                reg += int(instr[1])

    log.debug(f"{clock}: x = {reg}")

    return sum_of_signals, crt


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    lines = read_input(__file__)
    print(f"Star 1: {star1(lines)}")
    print(f"Star 2\n{star2(lines)}")

    # Star 1: 13760
    # Star 2: RFKZCPEF
