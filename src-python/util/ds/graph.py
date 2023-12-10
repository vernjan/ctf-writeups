from dataclasses import dataclass, field
from typing import List, Self, Any


@dataclass
class Node:
    id: Any
    neighbors: List = field(default_factory=list)

    def add_neighbor(self, neighbor: Self):
        self.neighbors.append(neighbor)
