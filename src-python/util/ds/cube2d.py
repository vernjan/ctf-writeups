from typing import List, Dict

from util.ds.coord import NORTH as N, EAST as E, SOUTH as S, WEST as W, Xy, Direction
from util.ds.coord import Xy
from util.ds.grid import Grid

"""Surface transitions between cube sides mapped into 2D"""
SURFACE_TRANSITIONS = {
    N: {
        N: lambda x, y, size: Xy(size - 1 - x, 0),  # 0
        E: lambda x, y, size: Xy(size - 1, size - 1 - x),  # 90
        S: lambda x, y, size: Xy(x, size - 1),  # 180
        W: lambda x, y, size: Xy(0, x),  # 270
    },
    E: {
        E: lambda x, y, size: Xy(size - 1, size - 1 - y),  # 0
        S: lambda x, y, size: Xy(y, size - 1),  # 90
        W: lambda x, y, size: Xy(0, y),  # 180
        N: lambda x, y, size: Xy(size - 1 - y, 0),  # 270
    },
    S: {
        S: lambda x, y, size: Xy(size - 1 - x, size - 1),  # 0
        W: lambda x, y, size: Xy(0, size - 1 - x),  # 90
        N: lambda x, y, size: Xy(x, 0),  # 180
        E: lambda x, y, size: Xy(size - 1, x),  # 270
    },
    W: {
        W: lambda x, y, size: Xy(0, size - 1 - y),  # 0
        N: lambda x, y, size: Xy(y, 0),  # 90
        E: lambda x, y, size: Xy(size - 1, y),  # 180
        S: lambda x, y, size: Xy(size - 1 - y, size - 1),  # 270
    }
}


def parse_2dcube(lines: List[str], cube_size: int) -> Grid:
    width = max(map(len, lines))
    height = len(lines)

    # pad shorter lines with empty spaces
    padded_lines = []
    for line in lines:
        row = line + (" " * (width - len(line)))
        padded_lines.append(row)

    rows = []
    for y in range(0, height, cube_size):
        row = []
        for x in range(0, width, cube_size):
            cube_side = Grid([line[x:x + cube_size] for line in padded_lines[y:y + cube_size]])
            row.append(cube_side)
        rows.append(row)

    return Grid(rows)


def get_cube_sides(cube2d: Grid) -> Dict[int, Grid]:
    """Return 6 cube sides numbered from 1"""
    cube_sides = {}
    for cube_side in cube2d.get_all_values():
        if cube_side.get_value(Xy(0, 0)) != " ":
            cube_sides[len(cube_sides) + 1] = cube_side

    assert len(cube_sides) == 6, "Exactly 6 cube sides expected"
    return cube_sides


def get_cube_sides_mapping(cube2d: Grid) -> List[Grid]:
    # TO-DO Implement ... Not so easy. See "aoc22/day22/data.py" for what should be returned.
    pass


def move(pos: Xy,
         steps: int,
         direction: Direction,
         stop_value=None,
         trace=False) -> "Grid":
    # TO-DO Use code "aoc22/day22/data.py", wrap it into an object.
    pass


def merge_cube2d(grid_of_grids: Grid, inner_grid_size: int) -> Grid:
    """Merge 2D cube (grid of grids) into a single grid - for printing, .."""
    merged_rows = []
    for y_master in range(grid_of_grids.height):
        for y_inner in range(inner_grid_size):
            merged_row = []
            for x_master in range(grid_of_grids.width):
                inner_grid = grid_of_grids.get_value(Xy(x_master, y_master))
                merged_row.extend(inner_grid.rows[y_inner])
            merged_rows.append(merged_row)
    return Grid(merged_rows)
