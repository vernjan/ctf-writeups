from dataclasses import dataclass, field
from typing import Self, Any


@dataclass
class Node:
    id: Any
    neighbors: list = field(default_factory=list)

    def add_neighbor(self, neighbor: Self):
        self.neighbors.append(neighbor)
