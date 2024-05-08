#pragma once

#include "aoc_utils.h"
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

using std::vector, std::string;


void read_file_data(const string &input_file, vector<string> &data);


struct RunResult {
    ulong result;
    long long int duration;
};

class StarBase {
public:
    StarBase(int day, int star) : day(day), star(star) {}

    void run_test(ulong expected_result, const string &input_file_name = "input-test.txt") {
        run_star(input_file_name, expected_result);
    }

    void run(ulong expected_result, const string &input_file_name = "input.txt") {

        RunResult result = run_star(input_file_name, expected_result);
        std::cout << "Star: " << star << ": " << result.result << " (" << result.duration << " ms)" << "\n";
    }

    [[nodiscard]] virtual ulong execute(const vector<string> &data) const = 0;


private:
    int day;
    int star;

    RunResult run_star(const string &input_file_name, ulong expected_result) const {
        const string data_dir = "../src/aoc21/day" + aoc::add_leading_zeroes(day, 2) + "/";
        vector<string> data;
        read_file_data(data_dir + input_file_name, data);

        auto start = std::chrono::high_resolution_clock::now();
        ulong result = execute(data);
        auto stop = std::chrono::high_resolution_clock::now();
        auto duration = duration_cast<std::chrono::milliseconds>(stop - start);
        if (expected_result > 0 && result != expected_result) {
            throw std::runtime_error("Expected " + std::to_string(expected_result) + " but got " + std::to_string(result));
        }
        return {result, duration.count()};
    }
};

void read_file_data(const string &input_file, vector<string> &data) {
    std::ifstream input("../src/" + input_file);
    if (!input.is_open()) {
        throw std::runtime_error("Could not open file: " + input_file);
    }
    string line;
    while (getline(input, line)) {
        data.push_back(line);
    }
}
