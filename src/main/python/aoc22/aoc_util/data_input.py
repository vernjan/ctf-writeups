def read_all_lines(filename):
    with open(filename, 'r') as data_input:
        return [line.rstrip() for line in (data_input.readlines())]
