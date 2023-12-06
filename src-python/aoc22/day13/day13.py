import functools
import json
import logging
from typing import List

from util.data_io import read_input, read_test_input
from util.log import log


@functools.total_ordering
class SignalList:
    def __init__(self, signals):
        self.signals = json.loads(signals)

    def __lt__(self, other):
        return self._compare_lists(self.signals, other.signals) < 0

    @staticmethod
    def _compare_lists(list1: List, list2: List) -> int:
        """Returns

          - negative number if list1 < list2
          - 0 if list1 == list2
          - positive number if list1 > list2
        """
        log.debug(f"{list1} vs. {list2}")

        i = 0
        while i < len(list1) and i < len(list2):
            item1 = list1[i]
            item2 = list2[i]
            i += 1

            if type(item1) is int and type(item2) is int:
                if item1 != item2:
                    return item1 - item2
            else:
                if type(item1) is int:
                    item1 = [item1]
                elif type(item2) is int:
                    item2 = [item2]
                sub_result = SignalList._compare_lists(item1, item2)
                if sub_result != 0:
                    return sub_result

        if len(list1) != len(list2):
            return len(list1) - len(list2)

        return 0

    def __str__(self):
        return str(self.signals)


def star1(lines: List[str]):
    """
    >>> star1(read_test_input(__file__))
    13
    """

    index_sum = 0
    pair_index = 0

    list1 = None
    list2 = None
    for i, line in enumerate(lines):
        if i % 3 == 0:
            list1 = SignalList(line)
        elif i % 3 == 1:
            list2 = SignalList(line)
        else:
            pair_index += 1
            log.debug(f">>> Comparing {list1} vs. {list2}")
            if list1 < list2:
                log.debug(f"Match found: i={i}, pair_index={pair_index}")
                index_sum += pair_index

    return index_sum


def star2(lines: List[str]):
    """
    >>> star2(read_test_input(__file__))
    140
    """

    divider1 = SignalList("[[2]]")
    divider2 = SignalList("[[6]]")

    all_signals = [divider1, divider2]
    for line in lines:
        if line:
            log.debug(f"Creating from line: {line}")
            all_signals.append(SignalList(line))

    all_signals.sort()
    log.debug(all_signals)

    return (all_signals.index(divider1) + 1) * (all_signals.index(divider2) + 1)


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    lines = read_input(__file__)
    print(f"Star 1: {star1(lines)}")
    print(f"Star 2: {star2(lines)}")

    # Star 1: 5557
    # Star 2: 22425
