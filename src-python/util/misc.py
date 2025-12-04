def expand_nonogram_groups(groups: list[int], total_size: int) -> list[str]:
    """
    >>> expand_nonogram_groups([1], 2)
    ['#_', '_#']
    >>> expand_nonogram_groups([1], 3)
    ['#__', '_#_', '__#']
    >>> expand_nonogram_groups([5], 6)
    ['#####_', '_#####']
    >>> expand_nonogram_groups([1, 1], 3)
    ['#_#']
    >>> expand_nonogram_groups([2, 1], 5)
    ['##_#_', '##__#', '_##_#']
    >>> expand_nonogram_groups([1, 1], 5)
    ['#_#__', '#__#_', '#___#', '_#_#_', '_#__#', '__#_#']
    """
    if not groups:
        return [""]
    group = groups[0]
    groups = groups[1:]
    group_size = group + 1 if groups else group  # last group doesn't need to end with .
    tail_size = sum(groups) + max(len(groups) - 1, 0)
    max_start = total_size - group_size - tail_size
    solutions = list()
    for i in range(max_start + 1):
        solution = ("_" * i) + ("#" * group) + ("_" * (1 if groups else total_size - i - group))
        for rec_solution in expand_nonogram_groups(groups, total_size - len(solution)):
            solutions.append(solution + "".join(rec_solution))
    return solutions
