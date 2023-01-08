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

SNAFU_THRESHOLD = 0.5693234419266027  # see _calc_snafu_threshold()


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    '2=-1=0'
    """

    return _dec2snafu(sum(map(_snafu2dec, lines)))


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


def _calc_snafu_threshold() -> None:
    """Exponent threshold value between SNAFU orders (e.g. between 222 (dec: 62) and 1=== (dec: 63)"""
    exp = math.log(_snafu2dec("22222222222222222222"), 5)  # float precision is limited but it's still okay
    _, dec_part = divmod(exp, 1)
    log.info(f"SNAFU threshold: {dec_part}")


def _dec2snafu(dec: int) -> str:
    """
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
    >>> _dec2snafu(12)
    '22'
    >>> _dec2snafu(13)
    '1=='
    >>> _dec2snafu(15)
    '1=0'
    >>> _dec2snafu(26)
    '101'
    >>> _dec2snafu(62)
    '222'
    >>> _dec2snafu(2022)
    '1=11-2'
    >>> _dec2snafu(314159265)
    '1121-1110-1=0'
    """

    if -2 <= dec <= 2:
        return DEC_TO_SNAFU[dec]

    snafu_order = _calc_snafu_order(dec)
    snafu_base = 5 ** snafu_order
    highest_number_starting_with_one = snafu_base + _snafu2dec("2" + "2" * (snafu_order - 1))
    snafu_value = 2 if abs(dec) > highest_number_starting_with_one else 1

    if dec < 0:
        snafu_value = -snafu_value

    snafu_digits = DEC_TO_SNAFU[snafu_value]

    next_dec = dec - snafu_value * snafu_base
    next_snafu_order = _calc_snafu_order(next_dec)
    for _ in range(next_snafu_order + 1, snafu_order):
        snafu_digits += "0"

    return snafu_digits + _dec2snafu(next_dec)


def _calc_snafu_order(dec):
    if dec == 0:
        return 0
    exp = math.log(abs(dec), 5)
    int_part, dec_part = divmod(exp, 1)
    return int(int_part) + (1 if dec_part >= SNAFU_THRESHOLD else 0)


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    _calc_snafu_threshold()
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    # There is no star 2 for this very last challenge

    # Star 1: 2-0=11=-0-2-1==1=-22
    # Star 2: No star
