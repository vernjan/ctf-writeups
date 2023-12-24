from dataclasses import dataclass
from typing import Deque, List, Any, Union, Sequence, Optional, TypeVar

from util.log import log

T = TypeVar("T")


@dataclass(frozen=True)
class RSequence:
    seq: Sequence[T]
    first_index: int

    @property
    def rsize(self) -> int:
        return len(self.seq) - self.first_index

    def __getitem__(self, index: int) -> T:
        """
        First detects a repeating sequence in the given list, then sums the given number of items.
        :return: sum of the given number of items
        >>> test_seq = [0,1,0,1,2,3]
        >>> RSequence(test_seq, first_index=3)[2]
        0
        >>> RSequence(test_seq, first_index=3)[4]
        2
        >>> RSequence(test_seq, first_index=3)[len(test_seq)]
        1
        >>> RSequence(test_seq, first_index=3)[len(test_seq) + 1]
        2
        >>> RSequence(test_seq, first_index=3)[len(test_seq) + 2]
        3
        """
        if index < len(self.seq):
            return self.seq[index]
        else:
            reminder_size = (index - self.first_index) % self.rsize
            return self.seq[self.first_index + reminder_size]

    def rsum(self, total_items: int) -> int:
        """
        First detects a repeating sequence in the given list, then sums the given number of items.
        :return: sum of the given number of items
        >>> test_seq = [0,1,0,1,2,3]
        >>> RSequence(test_seq, first_index=3).rsum(total_items=2)
        1
        >>> RSequence(test_seq, first_index=3).rsum(total_items=4)
        2
        >>> RSequence(test_seq, first_index=3).rsum(total_items=6)
        7
        >>> RSequence(test_seq, first_index=3).rsum(total_items=len(test_seq) + 2)
        10
        """
        if total_items <= len(self.seq):
            return sum(self.seq[:total_items])
        else:
            r_seq_count = (total_items - self.first_index) // self.rsize
            r_seq_sum = sum(self.seq[self.first_index:self.first_index + self.rsize])
            reminder_size = (total_items - self.first_index) % self.rsize
            reminder_sum = sum(self.seq[self.first_index:self.first_index + reminder_size])
            return sum(self.seq[:self.first_index]) + r_seq_count * r_seq_sum + reminder_sum

    def __repr__(self):
        return f"{self.seq}[{self.first_index}:]"


def find_rsequence(seq: Union[str | List[Any]], pattern_size: int, confidence: int = 3) -> Optional[RSequence]:
    """
    Detect a repeating sequence in the given list. By default, requires at least 3 occurences
    of the pattern (confidence).
    :return: first index of the repeating sequence, sequence size
    >>> find_rsequence([8,1,2,3,1,2,3,1,2,3], pattern_size=2, confidence=3)
    [8, 1, 2, 3][1:]
    >>> find_rsequence([1,2,3,4,5,6,1,2,3,4,5,6,1,2,3,4,5,6], pattern_size=2)
    [1, 2, 3, 4, 5, 6][0:]
    >>> find_rsequence("ffabcdabcd", pattern_size=2, confidence=2)
    ffabcd[2:]
    >>> find_rsequence([1,2,3,4,8,6,1,2,4,4,5,6,1,2,3,4,5,6], pattern_size=6)

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
        return None

    rseq_size = matches[1] - matches[0]
    for i in range(2, confidence):
        assert matches[i] - matches[i - 1] == rseq_size, \
            "Repeating pattern is not repeating, try a larger pattern size"

    rseq_size = matches[1] - matches[0]
    r_seq = seq[matches[0]:matches[1]]
    log.debug(f"Repeating sequence of size {rseq_size} detected: {r_seq}")

    first_index = matches[0]
    for i in range(1, rseq_size):
        shifted_repeating_seq = r_seq[-i:] + r_seq[:rseq_size - i]
        for seq_i in range(first_index):
            test = seq[seq_i:seq_i + rseq_size]
            if shifted_repeating_seq == test:
                first_index = seq_i
                log.debug(f"New repeating sequence start index found: {first_index}")
                break

    return RSequence(seq[:first_index + rseq_size], first_index)


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
