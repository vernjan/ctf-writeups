cmake_minimum_required(VERSION 3.26)
project(advent_of_code)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "-O3")

include_directories(
        include/
)

add_executable(AoC21Day00 src/aoc_utils.cpp src/aoc21/day00/day00.cpp)
add_executable(AoC21Day01 src/aoc_utils.cpp src/aoc21/day01/day01.cpp)
add_executable(AoC21Day02 src/aoc_utils.cpp src/aoc21/day02/day02.cpp)
add_executable(AoC21Day03 src/aoc_utils.cpp src/aoc21/day03/day03.cpp)
add_executable(AoC21Day04 src/aoc_utils.cpp src/aoc21/day04/day04.cpp)
add_executable(AoC21Day05 src/aoc_utils.cpp src/aoc21/day05/day05.cpp)
add_executable(AoC21Day06 src/aoc_utils.cpp src/aoc21/day06/day06.cpp)
add_executable(AoC21Day07 src/aoc_utils.cpp src/aoc21/day07/day07.cpp)
add_executable(AoC21Day08 src/aoc_utils.cpp src/aoc21/day08/day08.cpp)
add_executable(AoC21Day09 src/aoc_utils.cpp src/aoc21/day09/day09.cpp)
add_executable(AoC21Day10 src/aoc_utils.cpp src/aoc21/day10/day10.cpp)
add_executable(AoC21Day11 src/aoc_utils.cpp src/aoc21/day11/day11.cpp)
add_executable(AoC21Day12 src/aoc_utils.cpp src/aoc21/day12/day12.cpp)
add_executable(AoC21Day13 src/aoc_utils.cpp src/aoc21/day13/day13.cpp)
add_executable(AoC21Day14 src/aoc_utils.cpp src/aoc21/day14/day14.cpp)
add_executable(AoC21Day15 src/aoc_utils.cpp src/aoc21/day15/day15.cpp)
add_executable(MyVector src/my_vector.cpp)
