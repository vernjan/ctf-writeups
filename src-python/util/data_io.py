import os
import time
from typing import List

from util.log import log


def read_input(basefile: str, input_file: str = "input.txt") -> list[str]:
    return read_file(basefile, input_file)


def read_test_input(basefile: str, input_file: str = "input-test.txt") -> list[str]:
    return read_file(basefile, input_file)


def read_file(basefile: str, filename: str) -> list[str]:
    filename = os.path.join(os.path.dirname(basefile), filename)
    with open(filename, 'r') as data_input:
        return [line.rstrip() for line in (data_input.readlines())]


def timed_run(desc, m, expected_result = None):
    start = time.time()
    result = m()
    execution_time = round(time.time() - start, 3)
    if expected_result and expected_result != result:
        log.error(f"{desc} ({execution_time} sec): Expected result is {expected_result} but was {result}")
    else:
        log.info(f"{desc} ({execution_time} sec): {result}")
