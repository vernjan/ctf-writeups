import logging
import math

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    1227775554
    """
    result = 0
    for r in lines[0].split(","):
        start, end = map(int, r.split("-"))
        result += _sum_ids_in_range(start, end)
    return result


def _sum_ids_in_range(start: int, end: int) -> int:
    result = 0
    id = start
    while id <= end:
        if _is_invalid_id_s1(id):
            result += id
        id += 1 # TODO JVe jump to increase the first half of number

    return result


def _is_invalid_id_s1(id: int) -> bool:
    id_len = math.ceil(math.log10(id))
    # print(f"{id}: {id_len}")
    if id_len > 1 and id_len % 2 == 0:
        l = int(str(id)[0:id_len // 2])
        r = int(str(id)[id_len // 2:])
        return l == r
    return False



def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    4174379265
    """
    result = 0
    for r in lines[0].split(","):
        start, end = map(int, r.split("-"))
        result += _sum_ids_in_range2(start, end)
    return result


def _sum_ids_in_range2(start: int, end: int) -> int:
    result = 0
    id = start
    while id <= end:
        if _is_invalid_id_2(id):
            result += id
        id += 1 # TODO JVe jump to increase the first half of number

    return result


def _is_invalid_id_2(id: int) -> bool:
    id_len = math.ceil(math.log10(id))
    # print(f"{id}: {id_len}")
    if id_len > 1:
        if id_len % 2 == 0:
            l = int(str(id)[0:id_len // 2])
            r = int(str(id)[id_len // 2:])
            return l == r
        else:
            pass

    return False


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 20223751480
    # Star 2:
