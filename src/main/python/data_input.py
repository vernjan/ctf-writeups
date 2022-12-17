# TODO Rename file
import logging
from typing import List
import time


def read_all_lines(filename: str) -> List[str]:
    with open(filename, 'r') as data_input:
        return [line.rstrip() for line in (data_input.readlines())]


def read_single_line(filename: str) -> str:
    return read_all_lines(filename)[0]


def run(desc, m):
    start = time.time()
    result = m()
    execution_time = time.time() - start
    logging.info(f"{desc} ({execution_time}): {result}")
