from util.io import read_all_lines

elf_calories = []
current = 0

if __name__ == "__main__":

    for line in read_all_lines(__file__, "input.txt"):
        if line.isdigit():
            current += int(line)
        else:
            elf_calories.append(current)
            current = 0

    print(f"Star 1: {max(elf_calories)}")
    sum3max = sum(sorted(elf_calories, reverse=True)[:3])
    print(f"Star 2: {sum3max}")

# Star 1: 70369
# Star 2: 203002
