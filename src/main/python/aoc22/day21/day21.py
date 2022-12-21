import logging
from typing import List

from util.data_io import read_input, read_test_input, timed_run
from util.ds import FlatNode, TreeNode
from util.log import log


def star1(lines: List[str]):
    """
    >>> star1(read_test_input(__file__))
    152
    """

    nodes = _parse_flat_nodes(lines)
    root = TreeNode.from_nodes(nodes, "root")
    log.debug(root)

    return _eval_node(root)


def star2(lines: List[str]):
    """
    >>> star2(read_test_input(__file__))
    301
    """

    nodes = _parse_flat_nodes(lines)
    root = TreeNode.from_nodes(nodes, "root")
    log.debug(root)

    return _eval_human_node(root, None)


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


def _eval_human_node(node: TreeNode, node_value: int or None) -> int:
    if node.name == "humn":
        log.debug(f"Human value: {node_value}")
        return node_value

    if isinstance(node.value, int):
        return node.value

    if node.left.find_node("humn"):
        human_node = node.left
        monkeys_value = _eval_node(node.right)
    else:
        human_node = node.right
        monkeys_value = _eval_node(node.left)

    log.debug(f"Human node: {human_node.name}, monkeys value: {monkeys_value}")

    if node.name == "root":
        return _eval_human_node(human_node, monkeys_value)

    if node.value == "+":
        return _eval_human_node(human_node, node_value - monkeys_value)
    elif node.value == "-":
        if human_node == node.left:
            return _eval_human_node(human_node, node_value + monkeys_value)
        else:
            return _eval_human_node(human_node, monkeys_value - node_value)
    elif node.value == "*":
        return _eval_human_node(human_node, node_value // monkeys_value)
    elif node.value == "/":
        if human_node == node.left:
            return _eval_human_node(human_node, node_value * monkeys_value)
        else:
            return _eval_human_node(human_node, monkeys_value // node_value)
    else:
        raise ValueError("What???")


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 268597611536314
    # Star 2: 3451534022348
