from typing import Deque


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
