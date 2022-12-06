from typing import List


def read_all_lines(filename: str) -> List[str]:
    with open(filename, 'r') as data_input:
        return [line.rstrip() for line in (data_input.readlines())]


def read_single_line(filename: str) -> str:
    return read_all_lines(filename)[0]
