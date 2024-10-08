from typing import List

from util.data_io import read_input, read_test_input
from util.ds.grid import Grid, GridCell
from util.ds.coord import Xy, DIRECTIONS


def star1(lines: List[str]):
    """
    >>> star1(read_test_input(__file__))
    21
    """

    tree_counter = 0
    forest = Grid(lines)
    for _ in range(4):
        tree_counter += _count_visible_trees_from_side(forest)
        forest = forest.rotate_left()

    return tree_counter


def _count_visible_trees_from_side(forest: Grid) -> int:
    tree_counter = 0
    for x in range(forest.width):
        tree_line = forest.rows[x]
        max_height = -1
        for y in range(forest.height):
            tree = tree_line[y]
            tree_height = int(tree.value)
            if tree_height <= max_height:
                continue
            if tree_height < max_height:
                break
            max_height = tree_height
            if not tree.visited:
                tree.visited = True
                tree_counter += 1
    return tree_counter


def star2(lines: List[str]):
    """
    >>> star2(read_test_input(__file__))
    8
    """

    best_scenic_score = 0
    forest = Grid(lines)
    for y in range(forest.height):
        for x in range(forest.width):
            scenic_score = 1
            for direction in DIRECTIONS:
                _slice = forest.get_cells_from(Xy(x, y), direction)
                tree_count = _count_visible_trees_from_tree(_slice)
                scenic_score *= tree_count

            if scenic_score > best_scenic_score:
                best_scenic_score = scenic_score

    return best_scenic_score


def _count_visible_trees_from_tree(tree_slice: List[GridCell]) -> int:
    if len(tree_slice) == 1:
        return 0

    my_tree = tree_slice[0].value
    for i in range(1, len(tree_slice)):
        neighbor_tree = tree_slice[i].value
        if neighbor_tree >= my_tree:
            return i

    return len(tree_slice) - 1


if __name__ == "__main__":
    lines = read_input(__file__)
    print(f"Star 1: {star1(lines)}")
    print(f"Star 2: {star2(lines)}")

    # Star 1: 1713
    # Star 2: 268464
