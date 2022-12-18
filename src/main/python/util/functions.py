def signum(x):
    if x == 0:
        return 0
    if x < 0:
        return -1
    if x > 0:
        return 1


def array2d(width, height, value=None):
    return [[value] * width for _ in range(height)]
