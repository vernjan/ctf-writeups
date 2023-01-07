import logging
import math

from util.data_io import read_input, read_test_input, timed_run
from util.log import log

DEC_TO_SNAFU = {
    -2: "=",
    -1: "-",
    0: "0",
    1: "1",
    2: "2",
}

SNAFU_TO_DEC = {v: k for k, v in DEC_TO_SNAFU.items()}


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    '2=-1=0'

    """

    return _dec2snafu(sum(map(_snafu2dec, lines)))


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))

    """

    pass


def _snafu2dec(snafu: str) -> int:
    """
    >>> _snafu2dec("20")
    10
    >>> _snafu2dec("1=0")
    15
    >>> _snafu2dec("1=11-2")
    2022
    >>> _snafu2dec("1121-1110-1=0")
    314159265
    """

    dec = 0
    for i, value in enumerate(snafu):
        mult = 5 ** (len(snafu) - i - 1)
        dec += mult * SNAFU_TO_DEC[value]
    return dec


def _dec2snafu(dec: int) -> str:
    """
    >>> _dec2snafu(12)
    '22'
    >>> _dec2snafu(13)
    '1=='
    >>> _dec2snafu(26)
    '101'
    >>> _dec2snafu(-3)
    '-2'
    >>> _dec2snafu(2)
    '2'
    >>> _dec2snafu(3)
    '1='
    >>> _dec2snafu(5)
    '10'
    >>> _dec2snafu(6)
    '11'
    >>> _dec2snafu(7)
    '12'
    >>> _dec2snafu(9)
    '2-'
    >>> _dec2snafu(10)
    '20'
    >>> _dec2snafu(15)
    '1=0'
    >>> _dec2snafu(2022)
    '1=11-2'
    >>> _dec2snafu(314159265)
    '1121-1110-1=0'
    """

    snafu = []  # TODO return directl from rec function, this is not needed
    _dec2snafu_rec(dec, snafu)
    return "".join(snafu)


def _dec2snafu_rec(dec: int, snafu: list[str]) -> None:
    if -2 <= dec <= 2:
        snafu.append(DEC_TO_SNAFU[dec])
    else:
        order = int(round(math.log(abs(dec), 5), 0))
        base = 5 ** order
        foo = 2 * (5 ** (order - 1)) # TODO Name

        # if abs(dec) > base + foo or abs(dec) < base - foo:
        if abs(dec) > base + foo:
            value = 2
        else:
            value = 1

        if dec < 0:
            value = -value

        snafu.append(DEC_TO_SNAFU[value])

        next_dec = dec - value * base
        next_order = 0 if next_dec == 0 else int(round(math.log(abs(next_dec), 5), 0))
        for _ in range(next_order + 1, order):
            snafu.append("0")

        _dec2snafu_rec(next_dec, snafu)


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1:
    # Star 2:
