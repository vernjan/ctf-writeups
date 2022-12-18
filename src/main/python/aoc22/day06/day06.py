from my_io import read_single_line


def star1(datastream: str) -> int:
    """
    >>> star1("bvwbjplbgvbhsrlpgdmjqwftvncz")
    5
    >>> star1("nppdvjthqldpwncqszvftbrmjlhg")
    6
    >>> star1("nznrnfrfntjfmvfwmzdfjlvtqnbhcprsg")
    10
    >>> star1("zcfzfwzzqfrljwzlrfnpqdbhtmscgvjw")
    11
    """

    return _find_message_marker(datastream, 4)


def star2(datastream: str) -> int:
    """
    >>> star2("mjqjpqmgbljsphdztnvjfqwrcgsmlb")
    19
    >>> star2("bvwbjplbgvbhsrlpgdmjqwftvncz")
    23
    >>> star2("nppdvjthqldpwncqszvftbrmjlhg")
    23
    >>> star2("nznrnfrfntjfmvfwmzdfjlvtqnbhcprsg")
    29
    >>> star2("zcfzfwzzqfrljwzlrfnpqdbhtmscgvjw")
    26
    """

    return _find_message_marker(datastream, 14)


def _find_message_marker(datastream: str, slice_size: int) -> int:
    for i in range(len(datastream)):
        window = datastream[i:i + slice_size]
        if len(set(window)) == slice_size:
            return i + slice_size

    assert False, "Message marker not found"


if __name__ == "__main__":
    print(star1(read_single_line("input.txt")))
    print(star2(read_single_line("input.txt")))

    # Star 1: 1723
    # Star 2: 3708
