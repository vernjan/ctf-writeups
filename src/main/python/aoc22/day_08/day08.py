import pprint
from typing import List

from data_input import read_all_lines
from simple_logging import log


# TODO Refactor a generic a grid from it
class Grid:
    # data: List[str]

    def __init__(self, data: List[str]):
        self.rows = []
        self.cols = []

        self.visited = []
        for i in range(len(data)):
            row = [False for _ in range(len(data[0]))]
            self.visited.append(row)

        for row in data:
            self.rows.append([int(item) for item in row])

        # TODO row_size and col_size
        for col_index in range(len(data[0])):
            col = []
            for row_index in range(len(data)):
                col.append(int(data[row_index][col_index]))
            self.cols.append(col)

    def top_view(self):
        return self.cols

    def right_view(self):
        return [list(reversed(row)) for row in self.rows]

    def bottom_view(self):
        return [list(reversed(row)) for row in self.cols]

    def left_view(self):
        return self.rows

    def top_coordinates(self, rowi, coli):
        return coli, rowi

    def right_coordinates(self, rowi, coli):
        return rowi, len(self.cols[0]) - coli - 1

    def bottom_coordinates(self, rowi, coli):
        return len(self.cols[0]) - coli - 1, rowi

    def left_coordinates(self, rowi, coli):
        return rowi, coli

    def is_visited(self, i, j):
        return self.visited[i][j]

    def mark_visited(self, i, j):
        self.visited[i][j] = True


def star1(lines: List[str]):
    """
    >>> star1(read_all_lines("input-test.txt"))
    21
    """

    grid = Grid(lines)
    log.info(grid.top_view())
    log.info(grid.right_view())
    log.info(grid.bottom_view())
    log.info(grid.left_view())

    from_top = count_visible_trees(grid.top_view(), grid, grid.top_coordinates)
    log.info(pprint.pformat(grid.visited))
    from_right = count_visible_trees(grid.right_view(), grid, grid.right_coordinates)
    log.info(pprint.pformat(grid.visited))
    from_bottom = count_visible_trees(grid.bottom_view(), grid, grid.bottom_coordinates)
    log.info(pprint.pformat(grid.visited))
    from_left = count_visible_trees(grid.left_view(), grid, grid.left_coordinates)
    log.info(pprint.pformat(grid.visited))

    return from_top + from_right + from_bottom + from_left


def star2(lines: List[str]):
    """
    >>> star2(read_all_lines("input-test.txt"))
    'TODO'
    """

    pass


def count_visible_trees(forest: List[List[int]], grid, view_fc) -> int:
    counter = 0
    for i in range(len(forest)):
        tree_line = forest[i]
        max_height = -1
        for j in range(len(forest[0])):
            tree = tree_line[j]
            if tree <= max_height:
                continue
            if tree < max_height:
                break
            max_height = tree
            x, y = view_fc(i, j)
            if not grid.is_visited(x, y):
                grid.mark_visited(x, y)
                counter += 1
    return counter


if __name__ == "__main__":
    lines = read_all_lines("input.txt")
    print(f"Star 1: {star1(lines)}")
    print(f"Star 2: {star2(lines)}")

    # Star 1:
    # Star 2:
