# TODO Merge with Grid?
class VisualGrid:
    def __init__(self, width, height, empty_symbol="."):
        self.width = width
        self.height = height
        self.empty_symbol = empty_symbol
        self.rows = self._empty_grid()

    def _empty_grid(self):
        rows = []
        for _ in range(self.height):
            row = [self.empty_symbol for _ in range(self.width)]
            rows.append(row)
        return rows

    def clear(self):
        self.rows = self._empty_grid()

    def fprint(self):
        return "\n".join(["".join(row) for row in self.rows]) + "\n"
