from aoc_util.data_input import read_all_lines

sums = []
current = 0

for line in read_all_lines("day01/input.txt"):
    if line.isdigit():
        current += int(line)
    else:
        sums.append(current)
        current = 0

sums = sorted(sums, reverse=True)

print(f"Star 1: {sums[0]}")
sum3max = sums[0] + sums[1] + sums[2]
print(f"Star 2: {sum3max}")

# Star 1: 70369
# Star 2: 203002

