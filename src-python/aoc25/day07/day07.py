import logging

from ordered_set import OrderedSet

from util.data_io import read_input, read_test_input, timed_run
from util.ds.coord import Xy
from util.ds.grid import Grid
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    21
    """
    g = Grid(lines)
    start_pos = g.find_first("S")
    beams = OrderedSet([start_pos])
    splits = 0
    while beams:
        beam = beams.pop(0)
        new_pos = beam.south()
        if g.has(new_pos):
            if g[new_pos].value == '.':
                beams.append(new_pos)
            else:  # split ^
                splits += 1
                for new_beam in [new_pos.west(), new_pos.east()]:
                    if g.has(new_beam):
                        beams.append(new_beam)
    return splits


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    40
    """

    def add_beam(pos: Xy):
        if pos in beams:  # merging beams
            beams[pos] += beam_paths
        else:
            beams[pos] = beam_paths

    g = Grid(lines)
    start_pos = g.find_first("S")
    beams = {start_pos: 1}
    paths = 0
    while beams:
        beam_pos = next(iter(beams))
        beam_paths = beams.pop(beam_pos)
        new_pos = beam_pos.south()
        if g.has(new_pos):
            if g[new_pos].value == '.':
                add_beam(new_pos)
            else:  # split ^
                for split_pos in [new_pos.west(), new_pos.east()]:
                    if g.has(split_pos):
                        add_beam(split_pos)

        else:  # beam end
            paths += beam_paths
    return paths


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)), expected_result=1533)
    timed_run("Star 2", lambda: star2(read_input(__file__)), expected_result=10733529153890)
