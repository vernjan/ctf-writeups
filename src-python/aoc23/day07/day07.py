import logging
from functools import total_ordering

from util.data_io import read_input, read_test_input, timed_run
from util.log import log


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    6440
    """
    return solve(lines, use_jokers=False)


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))
    5905
    """
    return solve(lines, use_jokers=True)


def solve(lines, use_jokers: bool):
    hands_bids = []
    for line in lines:
        cards, bid = line.split()
        hands_bids.append((Hand(cards, use_jokers), bid))
    hands_bids.sort()
    total = 0
    for i in range(len(hands_bids)):
        total += (i + 1) * int(hands_bids[i][1])
    return total


@total_ordering
class Hand:

    def __init__(self, cards: str, use_jokers=False):
        self.cards = cards
        self.ranks = "J23456789TQKA" if use_jokers else "23456789TJQKA"
        self.use_jokers = use_jokers

    def __lt__(self, other):
        rank1 = self.get_rank()
        rank2 = other.get_rank()
        if rank1 != rank2:
            return rank1 < rank2
        else:
            for card1, card2 in zip(self.cards, other.cards):
                if card1 != card2:
                    return self.ranks.index(card1) < self.ranks.index(card2)
        return False

    def __eq__(self, other):
        return self.cards == other.cards

    def __repr__(self):
        return "".join(self.cards)

    def get_rank(self):
        counts = {}
        for c in self.cards:
            counts[c] = counts.get(c, 0) + 1

        if self.use_jokers:
            joker_count = counts.get("J", 0)
            if joker_count:
                del counts["J"]
        else:
            joker_count = 0

        if len(counts) <= 1:  # all same cards, 0 means all jokers
            return 7
        if len(counts) == 2:  # poker or full house
            # max 3 jokers
            if joker_count > 1:  # we can always make poker with 2 jokers
                return 6
            if joker_count == 1:  # poker if we already have 3 same cards, otherwise full house
                return 6 if 3 in counts.values() else 5
            return 6 if 4 in counts.values() else 5
        if len(counts) == 3:  # triple or two pairs
            # max 2 jokers
            if joker_count:  # either 2 jokers and 3 different cards -> triple; or 1 joker and 1 pair -> triple
                return 4
            return 4 if 3 in counts.values() else 3
        if len(counts) == 4:  # pair or 4 different and 1 joker
            return 2
        return 1  # high card, no joker


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 248836197
    # Star 2: 251195607
