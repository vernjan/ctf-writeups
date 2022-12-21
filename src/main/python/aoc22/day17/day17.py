import logging

from util.data_io import timed_run, read_input, read_test_input
from util.ds.grid import Grid
from util.log import log

ROW_PATTERN = [".", ".", "#", "#", "#", "#", "."]


# FIXME New Grid
class Rock:

    def __init__(self, grid: Grid, highest_y: int, width: int, height: int):
        self.grid = grid
        self.width = width
        self.height = height
        self.x_left = 2
        self.y = highest_y - 3 - self.height

    def move_left(self) -> bool:
        pass

    def move_right(self) -> bool:
        pass

    def move_down(self) -> bool:
        pass


class RectangleRock(Rock):

    def __init__(self, grid: Grid, highest_y: int, width: int, height: int):
        super().__init__(grid, highest_y, width, height)
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


class XRock(Rock):

    def __init__(self, grid: Grid, highest_y: int):
        super().__init__(grid, highest_y, 3, 3)
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


class LRock(Rock):

    def __init__(self, grid: Grid, highest_y: int):
        super().__init__(grid, highest_y, 3, 3)
        self.grid[self.y][4] = "#"
        self.grid[self.y + 1][4] = "#"
        for i in range(3):
            self.grid[self.y + 2][2 + i] = "#"

    def move_left(self):
        if self.x_left - 1 < 0:
            return False
        if self.grid[self.y][self.x_left + 1] != ".":
            return False
        if self.grid[self.y + 1][self.x_left + 1] != ".":
            return False
        if self.grid[self.y + 2][self.x_left - 1] != ".":
            return False
        self.grid[self.y][self.x_left + 2] = "."
        self.grid[self.y][self.x_left + 1] = "#"
        self.grid[self.y + 1][self.x_left + 2] = "."
        self.grid[self.y + 1][self.x_left + 1] = "#"
        self.grid[self.y + 2][self.x_left + 2] = "."
        self.grid[self.y + 2][self.x_left - 1] = "#"
        self.x_left -= 1
        return True

    def move_right(self):
        if self.x_left + self.width >= self.grid.width:
            return False
        for i in range(self.height):
            if self.grid[self.y + i][self.x_left + self.width] != ".":
                return False
        self.grid[self.y][self.x_left + 2] = "."
        self.grid[self.y][self.x_left + 3] = "#"
        self.grid[self.y + 1][self.x_left + 2] = "."
        self.grid[self.y + 1][self.x_left + 3] = "#"
        self.grid[self.y + 2][self.x_left] = "."
        self.grid[self.y + 2][self.x_left + 3] = "#"
        self.x_left += 1
        return True

    def move_down(self) -> bool:
        if self.y + self.height >= self.grid.height:
            return False
        for i in range(self.width):
            if self.grid[self.y + self.height][self.x_left + i] != ".":
                return False
        self.grid[self.y][self.x_left + 2] = "."
        self.grid[self.y + 3][self.x_left + 2] = "#"
        self.grid[self.y + 2][self.x_left] = "."
        self.grid[self.y + 3][self.x_left] = "#"
        self.grid[self.y + 2][self.x_left + 1] = "."
        self.grid[self.y + 3][self.x_left + 1] = "#"
        self.y += 1
        return True


class RockFactory:

    def __init__(self, grid: Grid):
        self.grid = grid

    def create(self, rock_type: int, highest_y: int) -> Rock:
        if rock_type == 0:
            return RectangleRock(self.grid, highest_y, width=4, height=1)
        elif rock_type == 1:
            return XRock(self.grid, highest_y)
        elif rock_type == 2:
            return LRock(self.grid, highest_y)
        elif rock_type == 3:
            return RectangleRock(self.grid, highest_y, width=1, height=4)
        elif rock_type == 4:
            return RectangleRock(self.grid, highest_y, width=2, height=2)
        else:
            assert False, "Shouldn't happen"


def star1(jets: str, rocks_count: int):
    """
    >>> star1(read_test_input(__file__)[0], 2022)
    3068
    """

    # log.setLevel(5)
    return simulate(jets, rocks_count)


def star2(jets: str, rocks_count: int):
    """
    >>> star2(read_test_input(__file__)[0], 1000000000000)
    1514285714288
    """

    # log.setLevel(5)
    return simulate(jets, rocks_count)


def simulate(jets: str, rocks_count: int):
    grid = Grid.empty(width=7, height=5_000, value=".")
    rock_factory = RockFactory(grid)
    jet_index = 0
    highest_y = grid.height
    repetition_patterns = {}
    pattern_found = False

    first_interval_height = None
    pattern_first_rock_number = None
    pattern_rock_count = None
    pattern_height = None
    last_interval_next_rock_number = None
    last_interval_highest_y = None

    for rock_number in range(rocks_count):
        rock_type = rock_number % 5
        rock = rock_factory.create(rock_type, highest_y)
        log.log(level=5, msg=f"New rock: number={rock_number}, type={rock_type}, y={rock.y}")
        log.log(level=5, msg=grid)

        while True:
            jet = jets[jet_index]
            log.log(level=5, msg=f"Jet i={jet_index} {jet}")
            jet_index = (jet_index + 1) % len(jets)
            log.log(level=5, msg=f"Moving rock: {jet}")
            if jet == "<":
                rock.move_left()
            elif jet == ">":
                rock.move_right()

            log.log(level=5, msg=grid)

            if rock.move_down():
                log.log(level=5, msg=f"Falling:")
                log.log(level=5, msg=grid)
            else:
                if not pattern_found and highest_y < grid.height and grid.rows[highest_y] == ROW_PATTERN:
                    pattern_key = (rock_type, jet_index)
                    if pattern_key in repetition_patterns:
                        pattern_found = True
                        previous_pattern_occurrence = repetition_patterns[pattern_key]
                        first_interval_height = grid.height - previous_pattern_occurrence[0]
                        first_interval_rock_count = previous_pattern_occurrence[1]
                        pattern_first_rock_number = previous_pattern_occurrence[1]
                        pattern_rock_count = rock_number - pattern_first_rock_number
                        pattern_height = grid.height - highest_y - first_interval_height
                        last_interval_rock_count = (rocks_count - pattern_first_rock_number) % pattern_rock_count
                        last_interval_next_rock_number = rock_number + last_interval_rock_count
                        last_interval_highest_y = highest_y

                        log.info(
                            f"Pattern found for key {pattern_key}: ({highest_y}, {rock_number}) <-- {previous_pattern_occurrence}:\n"
                            f" first_interval_rock_count={first_interval_rock_count}\n"
                            f" first_interval_height={first_interval_height}\n"
                            f" pattern_first_rock_number={pattern_first_rock_number}\n"
                            f" pattern_rock_count={pattern_rock_count}\n"
                            f" pattern_height={pattern_height}\n"
                            f" last_interval_rock_count={last_interval_rock_count}\n"
                            f" last_interval_rock_number={last_interval_next_rock_number}\n"
                            f" last_interval_highest_y={last_interval_highest_y}"
                        )
                    else:
                        pattern_value = (highest_y, rock_number)
                        log.debug(f"Saving pattern ({pattern_key}): {pattern_value}")
                        repetition_patterns[pattern_key] = pattern_value

                if last_interval_next_rock_number == rock_number:
                    log.debug("Last interval counted:")
                    last_interval_height = last_interval_highest_y - highest_y
                    log.info(f" last_interval_height: {last_interval_height}")
                    pattern_total_count = (rocks_count - pattern_first_rock_number) // pattern_rock_count
                    log.info(f" pattern_total_count: {pattern_total_count}")
                    total_height = first_interval_height + pattern_total_count * pattern_height + last_interval_height
                    return total_height

                if rock.y <= highest_y:
                    highest_y = rock.y

                break

    # log.debug(grid)

    return grid.height - highest_y


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)[0], 2022))
    timed_run("Star 2", lambda: star1(read_input(__file__)[0], 1000000000000))

    # Star 1: 3193
    # Star 2: 1577650429835
