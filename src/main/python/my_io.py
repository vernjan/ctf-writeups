import logging
import os
import time
from typing import List


def read_all_lines(filename: str) -> List[str]:
    logging.info(__file__)
    logging.info(os.path.basename(__file__))
    logging.info(os.path.curdir)

    # def txt_fn(script_path: str, suffix: str = '.txt') -> str:

    with open(filename, 'r') as data_input:
        return [line.rstrip() for line in (data_input.readlines())]


def read_single_line(filename: str) -> str:
    return read_all_lines(filename)[0]


def timed_run(desc, m):
    start = time.time()
    result = m()
    execution_time = round(time.time() - start, 3)
    logging.info(f"{desc} ({execution_time} sec): {result}")
