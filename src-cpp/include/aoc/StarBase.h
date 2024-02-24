#include <string>
#include <vector>
#include <fstream>

#pragma once

using std::vector, std::string;


class StarBase {
public:
    explicit StarBase(const string &input_file) {
        std::ifstream input("../src/" + input_file);
        if (!input.is_open()) {
            throw std::runtime_error("Could not open file: " + input_file);
        }
        string line;
        while (getline(input, line)) {
            lines.push_back(line);
        }
    }


    virtual int star1() const = 0;

    virtual int star2() const = 0;

protected:

    vector<string> lines;
};


