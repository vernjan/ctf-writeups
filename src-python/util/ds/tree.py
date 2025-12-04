from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class FlatNode:
    left: str
    right: str
    value: Any


@dataclass
class TreeNode:
    name: str
    left: "TreeNode | None"
    right: "TreeNode | None"
    value: Any
    depth: int

    @staticmethod
    def from_nodes(nodes: Dict[str, FlatNode], root_name: str, depth: int = 0) -> "TreeNode | None":
        if root_name is None:
            return None

        node = nodes[root_name]
        assert node, f"Node {root_name} doesn't exist"

        if node.left is None and node.right is None:
            return TreeNode(root_name, None, None, node.value, depth)

        left = TreeNode.from_nodes(nodes, node.left, depth + 1)
        right = TreeNode.from_nodes(nodes, node.right, depth + 1)
        return TreeNode(root_name, left, right, node.value, depth)

    def find_node(self, name: str) -> "TreeNode | None":
        return TreeNode._find_node(self, name)

    @staticmethod
    def _find_node(node: "TreeNode", name: str) -> "TreeNode | None":
        if node is None:
            return None
        if node.name == name:
            return node
        left = TreeNode._find_node(node.left, name)
        if left:
            return left
        return TreeNode.find_node(node.right, name)

    def __str__(self) -> str:
        padding = "--" * (self.depth + 1)
        left = ""
        if self.left:
            left = f"\n{padding} {self.left}"
        right = ""
        if self.right:
            right = f"\n{padding} {self.right}"
        return f"{self.name}: {self.value}{left}{right}"
