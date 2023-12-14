from typing import Deque, List, Tuple

from util.log import log


def signum(x: int) -> int:
    if x == 0:
        return 0
    if x < 0:
        return -1
    if x > 0:
        return 1


def array2d(width: int, height: int, value=None) -> list[str]:
    """Return new list of lists"""
    return [value * width for _ in range(height)]


def circular_shift(deq: Deque, index, steps) -> None:
    """Shift the element on the given index by the given number of steps.
    Use negative number of steps to shift left.
    """
    if steps % (len(deq) - 1) != 0:
        element = deq[index]
        del deq[index]
        new_index = (index + steps) % len(deq)
        deq.insert(new_index, element)


def find_repeating_sequence(seq: List, pattern_size: int, confidence: int = 3) -> Tuple[int, int]:
    """
    Detect a repeating sequence in the given list. Requires at least 3 occurences of the pattern.
    :return: first index of the repeating sequence, sequence size
    >>> find_repeating_sequence([8,1,2,3,1,2,3,1,2,3], pattern_size=2, confidence=3)
    (1, 3)
    >>> find_repeating_sequence([1,2,3,4,5,6,1,2,3,4,5,6,1,2,3,4,5,6], pattern_size=2)
    (0, 6)
    """
    assert confidence > 1, "Confidence must be at least 2"

    pattern = seq[len(seq) - pattern_size:]  # take last elements, best chance the sequence is already repeating
    log.debug(f"Looking for repeating pattern {pattern}")
    matches = []
    for seq_i in range(len(seq)):
        test = seq[seq_i:seq_i + pattern_size]
        if pattern == test:
            log.debug(f"Repeating pattern {pattern} found at {seq_i}")
            matches.append(seq_i)
            if len(matches) == confidence:
                break

    assert len(matches) == confidence, f"Repeating pattern was not found {confidence} times"

    r_seq_size = matches[1] - matches[0]
    for i in range(2, confidence):
        assert matches[i] - matches[i - 1] == r_seq_size, \
            "Repeating pattern is not repeating, try a larger pattern size"

    r_seq_size = matches[1] - matches[0]
    r_seq = seq[matches[0]:matches[1]]
    log.debug(f"Repeating sequence of size {r_seq_size} detected: {r_seq}")

    first_index = matches[0]
    for i in range(1, r_seq_size):
        shifted_repeating_seq = r_seq[-i:] + r_seq[:r_seq_size - i]
        for seq_i in range(first_index):
            test = seq[seq_i:seq_i + r_seq_size]
            if shifted_repeating_seq == test:
                first_index = seq_i
                log.debug(f"New repeating sequence start index found: {first_index}")
                break

    return first_index, r_seq_size
