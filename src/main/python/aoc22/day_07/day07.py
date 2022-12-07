import pprint
from typing import List
from typing import Dict

from data_input import read_all_lines
from simple_logging import log


def star1(dir_tree: Dict[str, Dict]):
    """
    >>> star1(_create_dir_tree(read_all_lines("input-test.txt")))
    95437
    """

    # TODO JVe Please, please refactor me ;-)
    total = {"x": 0}
    matching = list()
    _sum_dir(dir_tree, total, matching)
    log.info(matching)
    log.info(min(matching))

    return total["x"]


def star2(dir_tree: Dict[str, Dict]):
    """
    >>> star2(_create_dir_tree(read_all_lines("input-test.txt")))
    24933642
    """

    total = {"x": 0}
    matching = list()
    _sum_dir(dir_tree, total, matching)
    log.info(matching)

    return min(matching)

    # 1035571

    pass


def _create_dir_tree(commands: List[str]) -> Dict[str, Dict]:
    dir_stack = []
    dir_tree = {}
    for cmd in commands:
        if cmd == "$ cd ..":
            dir_stack.pop()
        elif cmd.startswith("$ cd "):
            if cmd == "$ cd /":
                dir_stack.clear()
            dirname = cmd[5:]
            parent_dir = _find_dir(dir_tree, dir_stack)
            if dirname not in parent_dir:
                parent_dir[dirname] = {}
            dir_stack.append(dirname)
        elif cmd.startswith("$ ls"):
            pass  # no-op
        elif cmd.startswith("dir "):
            dirname = cmd[4:]
            parent_dir = _find_dir(dir_tree, dir_stack)
            if dirname not in parent_dir:
                parent_dir[dirname] = {}
        else:
            size, filename = cmd.split(" ")
            parent_dir = _find_dir(dir_tree, dir_stack)
            if filename not in parent_dir:
                parent_dir[filename] = int(size)
    return dir_tree


def _find_dir(tree, dir_stack):
    for dir in dir_stack:
        tree = tree[dir]
    return tree


def _sum_dir(tree, total, matching):
    dirsize = 0
    for k, v in tree.items():
        if type(v) is dict:
            dirsize += _sum_dir(v, total, matching)
        else:
            dirsize += v

    if (dirsize <= 100_000):
        total["x"] += dirsize
    if (dirsize >= 1035571):
        matching.append(dirsize)

    return dirsize


if __name__ == "__main__":
    commands = read_all_lines("input.txt")
    dir_tree = _create_dir_tree(commands)
    log.info(f"Dir tree:\n{pprint.pformat(dir_tree)}")
    print(f"Star 1: {star1(dir_tree)}")
    print(f"Star 2: {star2(dir_tree)}")

    # Star 1: 1792222
    # Star 2: 1112963
