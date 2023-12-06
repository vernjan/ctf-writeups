import os
import time
from typing import List
from util.log import log


def read_input(basefile: str) -> List[str]:
    return read_file(basefile, "input.txt")


def read_test_input(basefile: str, input_file: str = "input-test.txt") -> List[str]:
    return read_file(basefile, input_file)


def read_file(basefile: str, filename: str) -> List[str]:
    filename = os.path.join(os.path.dirname(basefile), filename)
    with open(filename, 'r') as data_input:
        return [line.rstrip() for line in (data_input.readlines())]


def timed_run(desc, m):
    start = time.time()
    result = m()
    execution_time = round(time.time() - start, 3)
    log.info(f"{desc} ({execution_time} sec): {result}")
