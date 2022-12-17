import logging

from data_input import read_all_lines
from ds import Grid
from simple_logging import log


class Rock:

    def __init__(self, grid: Grid, max_y: int, width: int, height: int):
        self.grid = grid
        self.width = width
        self.height = height
        self.x_left = 2
        self.y = max_y - 3 - self.height

    def move_left(self) -> bool:
        pass

    def move_right(self) -> bool:
        pass

    def move_down(self) -> bool:
        pass


class RectangleRock(Rock):

    def __init__(self, grid: Grid, max_y: int, width: int, height: int):
        super().__init__(grid, max_y, width, height)

        for ri in range(self.height):
            for ci in range(self.width):
                self.grid[self.y + ri][2 + ci] = "#"

    def move_left(self):
        if self.x_left - 1 < 0:
            return False
        for i in range(self.height):
            if self.grid[self.y + i][self.x_left - 1] != ".":
                return False
        for i in range(self.height):
            self.grid[self.y + i][self.x_left + self.width - 1] = "."
            self.grid[self.y + i][self.x_left - 1] = "#"
        self.x_left -= 1
        return True

    def move_right(self):
        if self.x_left + self.width >= self.grid.width:
            return False
        for i in range(self.height):
            if self.grid[self.y + i][self.x_left + self.width] != ".":
                return False
        for i in range(self.height):
            self.grid[self.y + i][self.x_left] = "."
            self.grid[self.y + i][self.x_left + self.width] = "#"
        self.x_left += 1
        return True

    def move_down(self) -> bool:
        if self.y + self.height >= self.grid.height:
            return False
        for i in range(self.width):
            if self.grid[self.y + self.height][self.x_left + i] != ".":
                return False
        for i in range(self.width):
            self.grid[self.y][self.x_left + i] = "."
            self.grid[self.y + self.height][self.x_left + i] = "#"
        self.y += 1
        return True


class StarRock(Rock):

    def __init__(self, grid: Grid, max_y: int):
        super().__init__(grid, max_y, 3, 3)

        self.grid[self.y][3] = "#"
        for i in range(3):
            self.grid[self.y + 1][2 + i] = "#"
        self.grid[self.y + 2][3] = "#"

    def move_left(self):
        if self.x_left - 1 < 0:
            return False
        if self.grid[self.y][self.x_left] != ".":
            return False
        if self.grid[self.y + 1][self.x_left - 1] != ".":
            return False
        if self.grid[self.y + 2][self.x_left] != ".":
            return False
        self.grid[self.y][self.x_left + 1] = "."
        self.grid[self.y][self.x_left] = "#"
        self.grid[self.y + 1][self.x_left + 2] = "."
        self.grid[self.y + 1][self.x_left - 1] = "#"
        self.grid[self.y + 2][self.x_left + 1] = "."
        self.grid[self.y + 2][self.x_left] = "#"
        self.x_left -= 1
        return True

    def move_right(self):
        if self.x_left + self.width >= self.grid.width:
            return False
        if self.grid[self.y][self.x_left + 2] != ".":
            return False
        if self.grid[self.y + 1][self.x_left + 3] != ".":
            return False
        if self.grid[self.y + 2][self.x_left + 2] != ".":
            return False
        self.grid[self.y][self.x_left + 1] = "."
        self.grid[self.y][self.x_left + 2] = "#"
        self.grid[self.y + 1][self.x_left] = "."
        self.grid[self.y + 1][self.x_left + 3] = "#"
        self.grid[self.y + 2][self.x_left + 1] = "."
        self.grid[self.y + 2][self.x_left + 2] = "#"
        self.x_left += 1
        return True

    def move_down(self) -> bool:
        if self.y + self.height >= self.grid.height:
            return False
        if self.grid[self.y + 2][self.x_left] != ".":
            return False
        if self.grid[self.y + 3][self.x_left + 1] != ".":
            return False
        if self.grid[self.y + 2][self.x_left + 2] != ".":
            return False
        self.grid[self.y + 1][self.x_left] = "."
        self.grid[self.y + 2][self.x_left] = "#"
        self.grid[self.y][self.x_left + 1] = "."
        self.grid[self.y + 3][self.x_left + 1] = "#"
        self.grid[self.y + 1][self.x_left + 2] = "."
        self.grid[self.y + 2][self.x_left + 2] = "#"
        self.y += 1
        return True


class RockFactory:

    def __init__(self, grid: Grid):
        self.grid = grid

    def create(self, rock_type: int, max_y: int) -> Rock:
        return StarRock(self.grid, max_y)

        if rock_type == 0:
            return RectangleRock(self.grid, max_y, width=4, height=1)
        elif rock_type == 1:
            return StarRock(self.grid, max_y)  # TODO
        elif rock_type == 2:
            return RectangleRock(self.grid, max_y, width=4, height=1)  # TODO
        elif rock_type == 3:
            return RectangleRock(self.grid, max_y, width=1, height=4)
        elif rock_type == 4:
            return RectangleRock(self.grid, max_y, width=2, height=2)
        else:
            assert False, "Shouldn't happen"


def star1(jets: str, rocks_count: int):
    """
    >>> star1(read_all_lines("input-test.txt")[0], 5)
    3068
    """

    grid = Grid.empty(width=7, height=10, value=".")
    rock_factory = RockFactory(grid)
    jet_index = 0
    max_y = grid.height

    for rock_number in range(rocks_count):
        rock_type = rock_number % 5
        rock = rock_factory.create(rock_type, max_y)
        log.debug(f"New rock: number={rock_number}, type={rock_type}, y={rock.y}")
        log.debug(grid)

        while True:
            jet = jets[jet_index]
            log.debug(f"Moving rock: {jet}")
            if jet == "<":
                rock.move_left()
            elif jet == ">":
                rock.move_right()

            log.debug(grid)

            if rock.move_down():
                log.debug(f"Falling:")
                jet_index = (jet_index + 1) % len(jets)
                log.debug(grid)
            else:
                if rock.y < max_y:
                    max_y = rock.y
                break

    return max_y


def star2(jets: str, rocks_count: int):
    """
    >>> star2(read_all_lines("input-test.txt"))
    'TODO'
    """

    pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    jets = read_all_lines("input.txt")[0]
    print(f"Star 1: {star1(jets, 2022)}")
    print(f"Star 2: {star2(jets, 2022)}")

    # Star 1:
    # Star 2:
