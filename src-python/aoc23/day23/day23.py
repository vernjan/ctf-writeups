import logging
from typing import Set

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xy
from util.ds.grid import Grid
from util.log import log


# @dataclass
class SearchCtx:
    # _head: Xy
    # visited: Set[Xy] = field(default_factory=set)

    def __init__(self, head: Xy, visited: Set[Xy] = None):
        if visited is None:
            visited = set()
        self.visited = visited
        self.head = head

    @property
    def head(self) -> Xy:
        return self._head

    @head.setter
    def head(self, value: Xy) -> None:
        self._head = value
        self.visited.add(value)

    def fork(self, new_head: Xy) -> "SearchCtx":
        return SearchCtx(new_head, self.visited.copy())

    def __repr__(self) -> str:
        return f"SearchCtx(head={self.head}, visited={self.visited})"


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    94
    """
    grid = Grid(lines)
    start_pos = grid.find_first(".")
    end_pos = grid.find_last(".")
    queue = [SearchCtx(start_pos)]
    while queue:
        ctx = queue.pop(0)
        grid.set_value(ctx.head, "O")
        for n in grid.get_neighbors(ctx.head):
            n_cell = grid.get_cell(n)
            if n_cell.value in ".<>v^" and n not in ctx.visited:
                ctx.head = n
                queue.append(ctx)

    log.debug(grid)


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))

    """
    for line in lines:
        pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1:
    # Star 2:
