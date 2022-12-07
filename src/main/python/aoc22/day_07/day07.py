from typing import List
from simple_logging import log
import pprint

from data_input import read_all_lines

def _find_dir(tree, dirstack):
    search = tree
    for dir in dirstack:
        search = search[dir]
    return search



def _sum_dir(tree, total, matching):
    dirsize = 0
    for k, v in tree.items():
        if type(v) is dict:
            dirsize_temp = _sum_dir(v, total, matching)
            log.info(f"{k}: {dirsize_temp}")
            dirsize += dirsize_temp
        else:
            dirsize += v
    if (dirsize <= 100_000):
        total["x"] += dirsize
    if (dirsize >= 1035571):
        matching.append(dirsize)
    return dirsize


def star1(lines: List[str]):
    """
    >>> star1(read_all_lines("input-test.txt"))
    95437
    """
    total = 0
    dirstack = list()
    dirs = {}
    for line in lines:
        if line == "$ cd ..":
            dirstack.pop()
        elif line.startswith("$ cd "):
            if line == "$ cd  /":
                dirstack.clear()
            current_dir = line[5:]
            dir = _find_dir(dirs, dirstack)
            if current_dir not in dir:
                dir[current_dir] = {}
            dirstack.append(current_dir)
        elif line.startswith("$ ls"):
            pass  # no-op
        elif line.startswith("dir "):
            dirname = line[4:]
            dir = _find_dir(dirs, dirstack)
            if dirname not in dir:
                dir[dirname] = {}
        else:
            size, filename = line.split(" ")
            dir = _find_dir(dirs, dirstack)
            if filename not in dir:
                dir[filename] = int(size)

    # log.info(pprint.pprint(dirs))

    total = {"x": 0}
    matching = list()
    _sum_dir(dirs, total, matching)
    log.info(matching)
    log.info(min(matching))




    return total["x"]


def star2(lines: List[str]):
    """
    >>> star2(read_all_lines("input-test.txt"))
    'TODO'
    """

    # -11035571

    pass


if __name__ == "__main__":
    print(star1(read_all_lines("input.txt")))
    # print(star2(read_all_lines("input.txt")))

    # Star 1:
    # Star 2:
