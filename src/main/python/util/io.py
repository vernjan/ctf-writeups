import logging
import os
import time
from typing import List


def read_all_lines(basefile: str, filename: str) -> List[str]:
    filename = os.path.join(os.path.dirname(basefile), filename)

    with open(filename, 'r') as data_input:
        return [line.rstrip() for line in (data_input.readlines())]


def read_single_line(basefile: str, filename: str) -> str:
    return read_all_lines(basefile, filename)[0]


def timed_run(desc, m):
    start = time.time()
    result = m()
    execution_time = round(time.time() - start, 3)
    logging.info(f"{desc} ({execution_time} sec): {result}")
