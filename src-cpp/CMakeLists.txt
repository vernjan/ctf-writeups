cmake_minimum_required(VERSION 3.26)
project(advent_of_code)

set(CMAKE_CXX_STANDARD 20)

include_directories(
        include/
)

add_executable(AoC21Day00 src/aoc21/day00/day00.cpp)
add_executable(AoC21Day01 src/aoc21/day01/day01.cpp)
add_executable(AoC21Day02 src/aoc21/day02/day02.cpp)
add_executable(AoC21Day03 src/aoc21/day03/day03.cpp)
add_executable(AoC21Day04 src/aoc21/day04/day04.cpp)