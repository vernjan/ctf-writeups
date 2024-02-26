import logging
import re
import time
from typing import List

from util.data_io import read_input, read_test_input
from util.ds.coord import Xy as Pos
from util.log import log


def star1(lines: List[str], y):
    """
    >>> star1(read_test_input(__file__), 10)
    26
    """

    sensors_beacons = _parse_input_data(lines)
    return _calc_signal_coverage(sensors_beacons, y, subtract_beacons=True)[0]


def star2(lines: List[str], size_limit):
    """
    >>> star2(read_test_input(__file__), 21)
    56000011
    """

    """
    The solution is not optimal and takes tens of seconds.
    On the other hand, I just reused what I already have from execute 1 :-)
    """

    start = time.time()

    sensors_beacons = _parse_input_data(lines)
    for y in range(size_limit):
        signal_coverage, blocks = _calc_signal_coverage(sensors_beacons, y, subtract_beacons=False, limit=size_limit)
        log.debug(f"Signal coverage for y={y} is {signal_coverage}")
        if signal_coverage == size_limit - 1:
            log.info(f"!!! y={y}, blocks={blocks}")  # correct y=3429555

            # find x
            first_block = blocks[0]
            max_x = first_block[1]
            for block in blocks[1:]:
                if block[0] > max_x:
                    x = max_x
                    log.info(f"!!! x={x}")  # correct x=2749047
                    log.info(f"Time to complete: {time.time() - start}")
                    return x + (y * 4_000_000)
                if block[1] > max_x:
                    max_x = block[1]


def _parse_input_data(lines):
    sensors_beacons = []
    for line in lines:
        sx, bx = map(int, re.findall(r"x=(-?\d+)", line))
        sy, by = map(int, re.findall(r"y=(-?\d+)", line))
        sensor = Pos(sy, sx)
        beacon = Pos(by, bx)
        mdist = sensor.manhattan_dist(beacon)
        sensors_beacons.append((sensor, beacon, mdist))
        log.debug(f"Sensor: {sensor}, beacon: {beacon}, dist: {mdist}")
    return sensors_beacons


def _calc_signal_coverage(sensors_beacons: List, y: int, subtract_beacons: bool, limit=None):
    y_signal_blocks = []
    y_beacons = set()
    for sensor, beacon, mdist in sensors_beacons:
        signal_coverage = mdist - abs(sensor.y - y)
        if signal_coverage > 0:
            y_signal_blocks.append([sensor.x - signal_coverage, sensor.x + signal_coverage + 1])
        if subtract_beacons and beacon.y == y:
            y_beacons.add(beacon.x)

    y_signal_blocks.sort(key=lambda r: r[0])
    log.debug(f"y={y} signal blocks: {y_signal_blocks}")

    first_block = y_signal_blocks[0]
    max_block_end = first_block[1]
    total_signal_coverage = _count_signal_coverage_in_block(first_block[0], first_block[1], y_beacons, limit)
    for block in y_signal_blocks[1:]:
        block_start = block[0]
        block_end = block[1]
        if max_block_end > block_end:  # block is within previous blocks
            continue
        block_start = block_start if block_start > max_block_end else max_block_end
        total_signal_coverage += _count_signal_coverage_in_block(block_start, block_end, y_beacons, limit)
        max_block_end = block_end

    return total_signal_coverage, y_signal_blocks


def _count_beacons_in_block(block_start, block_end, beacons):
    count = 0
    for beacon in beacons:
        if block_start <= beacon < block_end:
            log.debug(f"Beacon found at {beacon}")
            count += 1
    return count


def _count_signal_coverage_in_block(block_start, block_end, beacons, limit):
    if limit:
        if block_start >= limit or block_end < 0:
            return 0
        block_start = max(0, block_start)
        block_end = min(limit, block_end)

    log.debug(f"2Block {block_start}-{block_end}")
    signal_coverage = abs(block_end - block_start)
    beacons_count = _count_beacons_in_block(block_start, block_end, beacons)
    return signal_coverage - beacons_count


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    lines = read_input(__file__)
    print(f"Star 1: {star1(lines, 2000000)}")
    print(f"Star 2: {star2(lines, 4_000_001)}")

    # Star 1: 6425133
    # Star 2: 10996191429555
