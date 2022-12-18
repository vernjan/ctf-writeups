import pprint
from typing import Dict
from typing import List

from util.io import read_all_lines
from util.logging import log


def star1(dir_tree: Dict[str, Dict]):
    """
    >>> star1(_create_dir_tree(read_all_lines(__file__, "input-test.txt")))
    95437
    """

    return sum(size for size in _get_all_dirsizes(dir_tree) if size <= 100_000)


def star2(dir_tree: Dict[str, Dict]):
    """
    >>> star2(_create_dir_tree(read_all_lines(__file__, "input-test.txt")))
    24933642
    """

    dirsizes = _get_all_dirsizes(dir_tree)
    occupied = max(dirsizes)
    max_occupied = 40_000_000
    delete_at_least = occupied - max_occupied
    return min(size for size in dirsizes if size >= delete_at_least)


def _create_dir_tree(commands: List[str]) -> Dict[str, Dict]:
    dirstack = []
    tree = {}
    for cmd in commands:
        if cmd == "$ cd ..":
            dirstack.pop()
        elif cmd.startswith("$ cd "):
            if cmd == "$ cd /":
                dirstack.clear()
            dirname = cmd[5:]
            parent_dir = _find_dir(tree, dirstack)
            if dirname not in parent_dir:
                parent_dir[dirname] = {}
            dirstack.append(dirname)
        elif cmd.startswith("$ ls"):
            pass  # no-op
        elif cmd.startswith("dir "):
            dirname = cmd[4:]
            parent_dir = _find_dir(tree, dirstack)
            if dirname not in parent_dir:
                parent_dir[dirname] = {}
        else:
            size, filename = cmd.split(" ")
            parent_dir = _find_dir(tree, dirstack)
            if filename not in parent_dir:
                parent_dir[filename] = int(size)
    return tree


def _find_dir(tree, dir_stack):
    for dir in dir_stack:
        tree = tree[dir]
    return tree


def _get_all_dirsizes(tree: Dict[str, Dict]) -> List[int]:
    dirsizes = []
    _collect_dirsizes(tree, dirsizes)
    return dirsizes


def _collect_dirsizes(tree: Dict[str, Dict], dirsizes: List[int]) -> int:
    dirsize = 0
    for dirname, v in tree.items():
        if type(v) is dict:
            dirsize += _collect_dirsizes(v, dirsizes)
        else:
            dirsize += v

    dirsizes.append(dirsize)

    return dirsize


if __name__ == "__main__":
    commands = read_all_lines(__file__, "input.txt")
    dir_tree = _create_dir_tree(commands)
    log.info(f"Dir tree:\n{pprint.pformat(dir_tree)}")
    print(f"Star 1: {star1(dir_tree)}")
    print(f"Star 2: {star2(dir_tree)}")

    # Star 1: 1792222
    # Star 2: 1112963
