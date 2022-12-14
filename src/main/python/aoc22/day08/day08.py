from typing import List

from ds import Grid, Position
from data_input import read_all_lines


def star1(lines: List[str]):
    """
    >>> star1(read_all_lines("input-test.txt"))
    21
    """

    tree_counter = 0
    forest = Grid(lines)
    for direction in Grid.DIRECTIONS:
        tree_counter += _count_visible_trees_from_side(forest, direction)

    return tree_counter


def _count_visible_trees_from_side(forest: Grid, direction: str) -> int:
    forest_view = forest.view_from(direction)
    tree_counter = 0
    for coli in range(forest.width):
        tree_line = forest_view[coli]
        max_height = -1
        for rowi in range(forest.width):
            tree_height = int(tree_line[rowi])
            if tree_height <= max_height:
                continue
            if tree_height < max_height:
                break
            max_height = tree_height
            if not forest.is_visited(coli, rowi, direction):
                forest.mark_visited(coli, rowi, direction)
                tree_counter += 1
    return tree_counter


def star2(lines: List[str]):
    """
    >>> star2(read_all_lines("input-test.txt"))
    8
    """

    best_scenic_score = 0
    forest = Grid(lines)
    for rowi in range(forest.height):
        for coli in range(forest.width):
            scenic_score = 1
            for direction in Grid.DIRECTIONS:
                _slice = forest.slice_at(Position(rowi, coli), direction)
                tree_count = _count_visible_trees_from_tree(_slice)
                scenic_score *= tree_count

            if scenic_score > best_scenic_score:
                best_scenic_score = scenic_score

    return best_scenic_score


def _count_visible_trees_from_tree(tree_slice: List[int]) -> int:
    if len(tree_slice) == 1:
        return 0

    my_tree = tree_slice[0]
    for i in range(1, len(tree_slice)):
        neighbor_tree = tree_slice[i]
        if neighbor_tree >= my_tree:
            return i

    return len(tree_slice) - 1


if __name__ == "__main__":
    lines = read_all_lines("input.txt")
    print(f"Star 1: {star1(lines)}")
    print(f"Star 2: {star2(lines)}")

    # Star 1: 1713
    # Star 2: 268464
