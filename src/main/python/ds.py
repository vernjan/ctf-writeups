from typing import Iterable, List, Tuple


# TODO Typing for all
# TODO Docs
# TODO GridCell? No transposing?
class Grid:
    class Cell:
        def __int__(self, rowi, coli, val):
            self.rowi = rowi
            self.coli = coli
            self.val = val
            self.visited = False

    DIRECTIONS = ["UP", "RIGHT", "DOWN", "LEFT"]  # TODO vs. Views?

    # TODO Clean up
    def __init__(self, data: List[str]):
        self.rows = []
        self.cols = []

        # for rowi in range(len(data)):

        # FIXME !!! str vs int
        for row in data:
            # self.rows.append([int(item) for item in row])
            self.rows.append([item for item in row])

        # TODO row_size and col_size
        for coli in range(len(data[0])):
            col = []
            for row_index in range(len(data)):
                # col.append(int(data[row_index][coli]))
                col.append(data[row_index][coli])
            self.cols.append(col)

        # TODO More Pythonic way?
        self.visited = []
        for _ in range(self.cols_count()):
            row = [False for _ in range(self.rows_count())]
            self.visited.append(row)

    def __getitem__(self, item):
        return self.rows[item]

    # TODO find_all, better impl?
    def find_one(self, value):
        for i in range(len(self.rows)):
            row = self.rows[i]
            for j in range(len(row)):
                if row[j] == value:
                    return i, j
        assert False, "Not found"

    def at_pos(self, pos: Tuple[int, int]):
        return self[pos[0]][pos[1]]

    def rows_count(self) -> int:
        return len(self.rows)

    def cols_count(self) -> int:
        return len(self.cols)

    def slice_from(self, rowi, coli, direction) -> Iterable:
        """Get a grid slice from the given position moving into the given direction"""
        if direction == "UP":
            return self.cols[coli][rowi::-1]
        elif direction == "RIGHT":
            return self.rows[rowi][coli:]
        elif direction == "DOWN":
            return self.cols[coli][rowi:]
        elif direction == "LEFT":
            return self.rows[rowi][coli::-1]
        else:
            raise ValueError(f"Invalid direction: {direction}")

    # TODO Rotate?
    def view_from(self, direction):
        """Transpose the grid as if looked from the given direction"""
        if direction == "UP":
            return self.cols
        elif direction == "RIGHT":
            return [list(reversed(row)) for row in self.rows]
        elif direction == "DOWN":
            return [list(reversed(row)) for row in self.cols]
        elif direction == "LEFT":
            return self.rows
        else:
            raise ValueError(f"Invalid direction: {direction}")

    def is_visited(self, i, j, view_from="LEFT"):
        rowi, coli = self._transpose_coordinates(i, j, view_from)
        return self.visited[rowi][coli]

    def mark_visited(self, i, j, view_from="LEFT"):
        rowi, coli = self._transpose_coordinates(i, j, view_from)
        self.visited[rowi][coli] = True

    def _transpose_coordinates(self, rowi, coli, view_from):
        if view_from == "UP":
            return coli, rowi
        elif view_from == "RIGHT":
            return rowi, len(self.cols[0]) - coli - 1
        elif view_from == "DOWN":
            return len(self.cols[0]) - coli - 1, rowi
        elif view_from == "LEFT":
            return rowi, coli
        else:
            raise ValueError(f"Invalid direction: {view_from}")
