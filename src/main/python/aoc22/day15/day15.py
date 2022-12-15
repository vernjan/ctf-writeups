import logging
import re
from typing import List

from data_input import read_all_lines
from ds import Position as Pos
from simple_logging import log


def star1(lines: List[str], y):
    """
    >>> star1(read_all_lines("input-test.txt"), 10)
    26
    """

    sensors_beacons = parse_input_data(lines)
    return calc_occupied(sensors_beacons, y)


def star2(lines: List[str], y):
    """
    >>> star2(read_all_lines("input-test.txt"), 10)
    56000011
    """

    import time
    start = time.time()

    sensors_beacons = parse_input_data(lines)
    for y in range(3429555, 3429555 + 1):
        occ = calc_occupied(sensors_beacons, y)
        if occ < 4_000_001:
            log.info(f"Y={y}, occ={occ}")
            # break
    log.info(time.time() - start)


def parse_input_data(lines):
    sensors_beacons = []
    for line in lines:
        sx, bx = map(int, re.findall(r"x=(-?\d+)", line))
        sy, by = map(int, re.findall(r"y=(-?\d+)", line))
        sensor = Pos(sy, sx)
        beacon = Pos(by, bx)
        log.debug(f"Sensor: {sensor}, beacon: {beacon}")
        mdist = sensor.manhattan_dist(beacon)
        sensors_beacons.append((sensor, beacon, mdist))
    return sensors_beacons


def calc_occupied(lines, y):
    y_signal_blocks = []
    y_beacons = set()
    for sensor, beacon, mdist in lines:
        signal_coverage = mdist - abs(sensor.ri - y)
        if signal_coverage > 0:
            y_signal_blocks.append([sensor.ci - signal_coverage, sensor.ci + signal_coverage + 1])
        # if beacon.ri == y:
        #     y_beacons.add(beacon.ci)

    y_signal_blocks.sort(key=lambda r: r[0])
    log.debug(f"y signal blocks: {y_signal_blocks}")
    # log.debug(f"y beacon positions: {y_beacons}")

    first_block = y_signal_blocks[0]
    max_block_end = first_block[1]
    total_signal_coverage = count_signal_coverage_in_block(first_block[0], first_block[1], y_beacons)
    for block in y_signal_blocks[1:]:
        block_end = block[1]
        if max_block_end > block_end:  # block is within
            continue
        block_start = block[0] if block[0] > max_block_end else max_block_end
        total_signal_coverage += count_signal_coverage_in_block(block_start, block_end, y_beacons)
        max_block_end = block_end

    return total_signal_coverage


def count_beacons_in_block(block_start, block_end, beacons):
    count = 0
    for beacon in beacons:
        if block_start <= beacon < block_end:
            log.debug(f"Beacon found at {beacon}")
            count += 1
    return count


def count_signal_coverage_in_block(block_start, block_end, beacons):
    block_start = max(0, block_start)
    block_end = min(4_000_001, block_end)

    log.debug(f"Block {block_start}-{block_end}")
    signal_coverage = abs(block_end - block_start)
    # beacons_count = count_beacons_in_block(block_start, block_end, beacons)
    beacons_count = 0
    return signal_coverage - beacons_count


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    lines = read_all_lines("input.txt")
    # print(f"Star 1: {star1(lines, 2000000)}")
    print(f"Star 2: {star2(lines, 2000000)}")

    # Star 1: 6425133
    # Star 2:
