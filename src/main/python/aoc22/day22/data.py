from util.ds.coord import NORTH as N, EAST as E, SOUTH as S, WEST as W

"""Map cube sides to their neighbors including their orientation"""

CUBE_TEST = {
    1: {
        N: (2, N),
        E: (6, E),
        S: (4, N),
        W: (3, N),
    },
    2: {
        N: (1, N),
        E: (3, W),
        S: (5, S),
        W: (6, S),
    },
    3: {
        N: (1, W),
        E: (4, W),
        S: (5, W),
        W: (2, E),
    },
    4: {
        N: (1, S),
        E: (6, N),
        S: (5, N),
        W: (3, S),
    },
    5: {
        N: (4, S),
        E: (6, W),
        S: (2, S),
        W: (3, S),
    },
    6: {
        N: (4, E),
        E: (1, E),
        S: (2, W),
        W: (5, E),
    },
}

CUBE = {
    1: {
        N: (6, W),
        E: (2, W),
        S: (3, N),
        W: (4, W),
    },
    2: {
        N: (6, S),
        E: (5, E),
        S: (3, E),
        W: (1, E),
    },
    3: {
        N: (1, S),
        E: (2, S),
        S: (5, N),
        W: (4, N),
    },
    4: {
        N: (3, W),
        E: (5, W),
        S: (6, N),
        W: (1, W),
    },
    5: {
        N: (3, S),
        E: (2, E),
        S: (6, E),
        W: (4, E),
    },
    6: {
        N: (4, S),
        E: (5, S),
        S: (2, N),
        W: (1, N),
    },
}
