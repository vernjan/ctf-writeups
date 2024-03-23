#pragma once

#include <chrono>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

using std::vector, std::string;


void read_file_data(const string &input_file, vector<string> &data);

string to_zero_lead(int value, int precision);

std::vector<std::string> split(string text, const string &delimiter);

int btoi(const string &binary);


struct RunResult {
    int result;
    long long int duration;
};

class StarBase {
public:
    StarBase(int day, int star) : day(day), star(star) {}

    void run_test(int expected_result, const string &input_file_name = "input-test.txt") {
        run_star(input_file_name, expected_result);
    }

    void run(int expected_result, const string &input_file_name = "input.txt") {

        RunResult result = run_star(input_file_name, expected_result);
        std::cout << "Star: " << star << ": " << result.result << " (" << result.duration << " ms)" << "\n";
    }

    [[nodiscard]] virtual int execute(const vector<string> &data) const = 0;


private:
    int day;
    int star;

    RunResult run_star(const string &input_file_name, int expected_result) const {
        const string data_dir = "../src/aoc21/day" + to_zero_lead(day, 2) + "/";
        vector<string> data;
        read_file_data(data_dir + input_file_name, data);

        auto start = std::chrono::high_resolution_clock::now();
        int result = execute(data);
        auto stop= std::chrono::high_resolution_clock::now();
        auto duration = duration_cast<std::chrono::milliseconds>(stop - start);
        if (expected_result > 0 && result != expected_result) {
            throw std::runtime_error("Expected " + std::to_string(expected_result) + " but got " + std::to_string(result));
        }
        return {result, duration.count()};
    }
};


// utils

std::vector<std::string> split(string text, const string &delimiter) {
    std::vector<std::string> tokens;
    size_t pos = 0;
    std::string token;
    while ((pos = text.find(delimiter)) != std::string::npos) {
        token = text.substr(0, pos);
        tokens.push_back(token);
        text.erase(0, pos + delimiter.length());
    }
    tokens.push_back(text);
    return tokens;
}


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

string to_zero_lead(int value, int precision) {
    std::ostringstream oss;
    oss << std::setw(precision) << std::setfill('0') << value;
    return oss.str();
}

int btoi(const string &binary) {
    return std::stoi(binary, nullptr, 2);
}
