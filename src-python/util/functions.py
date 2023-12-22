from typing import Deque, List, Tuple, Any, Union, Sequence

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


def find_rsequence(seq: Union[str | List[Any]], pattern_size: int, confidence: int = 3) -> Tuple[int, int]:
    """
    Detect a repeating sequence in the given list. By default, requires at least 3 occurences
    of the pattern (confidence).
    :return: first index of the repeating sequence, sequence size
    >>> find_rsequence([8,1,2,3,1,2,3,1,2,3], pattern_size=2, confidence=3)
    (1, 3)
    >>> find_rsequence([1,2,3,4,5,6,1,2,3,4,5,6,1,2,3,4,5,6], pattern_size=2)
    (0, 6)
    >>> find_rsequence("ffabcdabcd", pattern_size=2, confidence=2)
    (2, 4)
    >>> find_rsequence([1,2,3,4,8,6,1,2,4,4,5,6,1,2,3,4,5,6], pattern_size=6)
    (-1, 0)
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

    if len(matches) < confidence:
        return -1, 0

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


def get_rsequence_item(seq: Union[str | List[Any]],
                       seq_index: int,
                       pattern_size: int,
                       confidence: int = 3) -> int:
    """
    First detects a repeating sequence in the given list, then sums the given number of items.
    :return: sum of the given number of items
    >>> get_rsequence_item([0,1,0,1,2,3,1,2,3,1,2,3], seq_index=2, pattern_size=3)
    0
    >>> get_rsequence_item([0,1,0,1,2,3,1,2,3,1,2,3], seq_index=4, pattern_size=3)
    2
    >>> test_seq = [0,1,0,1,2,3,1,2,3,1,2,3]
    >>> get_rsequence_item(test_seq, seq_index=len(test_seq), pattern_size=3)
    1
    >>> get_rsequence_item(test_seq, seq_index=len(test_seq) + 1, pattern_size=3)
    2
    >>> get_rsequence_item(test_seq, seq_index=len(test_seq) + 2, pattern_size=3)
    3
    """
    first_index, r_seq_size = find_rsequence(seq, pattern_size=pattern_size, confidence=confidence)
    assert first_index >= 0, "Repeating sequence not found"

    if seq_index < len(seq):
        return seq[seq_index]
    else:
        reminder_size = (seq_index - first_index) % r_seq_size
        return seq[first_index + reminder_size]


def sum_rsequence(seq: Union[str | Sequence[Any]],
                  total_items: int,
                  pattern_size: int,
                  confidence: int = 3) -> int:
    """
    First detects a repeating sequence in the given list, then sums the given number of items.
    :return: sum of the given number of items
    >>> sum_rsequence([2,2,2,2,2], total_items=2, pattern_size=2)
    4
    >>> sum_rsequence([2,2,2,2,2], total_items=8, pattern_size=2)
    16
    >>> sum_rsequence([0,1,0,1,2,3,1,2,3,1,2,3], total_items=2, pattern_size=3)
    1
    >>> sum_rsequence([0,1,0,1,2,3,1,2,3,1,2,3], total_items=6, pattern_size=3)
    7
    >>> sum_rsequence([0,1,0,1,2,3,1,2,3,1,2,3], total_items=7, pattern_size=3)
    8
    >>> test_seq = [0,1,0,1,2,3,1,2,3,1,2,3]
    >>> sum_rsequence(test_seq, total_items=len(test_seq) + 1, pattern_size=3)
    20
    """
    first_index, r_seq_size = find_rsequence(seq, pattern_size=pattern_size, confidence=confidence)
    assert first_index >= 0, "Repeating sequence not found"

    if total_items <= len(seq):
        return sum(seq[:total_items])
    else:
        r_seq_count = (total_items - first_index) // r_seq_size
        r_seq_sum = sum(seq[first_index:first_index + r_seq_size])
        reminder_size = (total_items - first_index) % r_seq_size
        reminder_sum = sum(seq[first_index:first_index + reminder_size])
        return sum(seq[:first_index]) + r_seq_count * r_seq_sum + reminder_sum
