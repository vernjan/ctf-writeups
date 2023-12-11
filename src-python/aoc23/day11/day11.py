import logging

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xy
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    374
    """
    expanded_rows = []
    expanded_cols = []

    width = len(lines)
    for i in range(width):
        row_has_galaxy = False
        col_has_galaxy = False
        for j in range(width):
            if lines[i][j] == "#":
                row_has_galaxy = True
            if lines[j][i] == "#":
                col_has_galaxy = True
        if not row_has_galaxy:
            expanded_rows.append(i)
        if not col_has_galaxy:
            expanded_cols.append(i)

    log.debug(expanded_rows)
    log.debug(expanded_cols)

    galaxies = []
    for y in range(width):
        for x in range(width):
            if lines[y][x] == "#":
                y_expansion = 0
                x_expansion = 0
                for expanded_row in expanded_rows:
                    if y > expanded_row:
                        y_expansion += 1
                    else:
                        break
                for expanded_col in expanded_cols:
                    if x > expanded_col:
                        x_expansion += 1
                    else:
                        break
                galaxies.append(Xy(x + x_expansion, y + y_expansion))

    log.debug(galaxies)

    total = 0
    while galaxies:
        galaxy = galaxies.pop()
        for other_galaxy in galaxies:
            log.debug("Calculating distance between {} and {}".format(galaxy, other_galaxy))
            total +=1

    return total


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
