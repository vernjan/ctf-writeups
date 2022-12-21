import logging
from dataclasses import dataclass
from typing import List, Any, Dict

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


# TODO Move to ds

@dataclass
class FlatNode:
    left: str
    right: str
    value: Any


@dataclass
class TreeNode:
    name: str
    left: "TreeNode" or None
    right: "TreeNode" or None
    value: Any
    depth: int

    @staticmethod
    def from_nodes(nodes: Dict[str, FlatNode], root_name: str, depth: int = 0) -> "TreeNode" or None:
        if root_name is None:
            return None

        node = nodes[root_name]
        assert node, f"Node {root_name} doesn't exist"

        if node.left is None and node.right is None:
            return TreeNode(root_name, None, None, node.value, depth)

        left = TreeNode.from_nodes(nodes, node.left, depth + 1)
        right = TreeNode.from_nodes(nodes, node.right, depth + 1)
        return TreeNode(root_name, left, right, node.value, depth)

    def __str__(self) -> str:
        padding = "--" * (self.depth + 1)
        left = ""
        if self.left:
            left = f"\n{padding} {self.left}"
        right = ""
        if self.right:
            right = f"\n{padding} {self.right}"
        return f"{self.name}: {self.value}{left}{right}"


def star1(lines: List[str]):
    """
    >>> star1(read_test_input(__file__))
    152
    """

    nodes = _parse_flat_nodes(lines)
    root = TreeNode.from_nodes(nodes, "root")
    log.debug(root)

    return _eval_node(root)


def _eval_node(node: TreeNode) -> int:
    if isinstance(node.value, int):
        return node.value

    left = _eval_node(node.left)
    right = _eval_node(node.right)

    if node.value == "+":
        return left + right
    elif node.value == "-":
        return left - right
    elif node.value == "*":
        return left * right
    elif node.value == "/":
        return left // right
    else:
        raise ValueError("What???")


def _parse_flat_nodes(lines):
    nodes = {}
    for node in lines:
        parts = node.split(" ")
        name = parts[0][0:-1]
        left, right = None, None
        if parts[1].isnumeric():
            value = int(parts[1])
        else:
            left, right = parts[1], parts[3]
            value = parts[2]
        nodes[name] = FlatNode(left, right, value)
    log.debug(nodes)
    return nodes


def star2(lines: List[str]):
    """
    >>> star2(read_test_input(__file__))
    301
    """

    pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 268597611536314
    # Star 2:
