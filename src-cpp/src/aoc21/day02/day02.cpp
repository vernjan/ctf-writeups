#include <iostream>
#include <vector>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>

using namespace std;

struct S1 : public StarBase {
    S1() : StarBase(2, 1) {}

    [[nodiscard]] ulong execute(const vector<string> &data) const override {
        int depth = 0;
        int forward = 0;
        for (const string &line: data) {
            vector<string> tokens = aoc::split(line, " ");
            string cmd = tokens[0];
            int steps = stoi(tokens[1]);
            if (cmd == "forward") {
                forward += steps;
            } else if (cmd == "up") {
                depth -= steps;
            } else if (cmd == "down") {
                depth += steps;
            } else {
                throw std::runtime_error("Unknown command: " + cmd);
            }
        }
        return depth * forward;
    }
};

struct S2 : public StarBase {
    S2() : StarBase(2, 2) {}

    [[nodiscard]] ulong execute(const vector<string> &data) const override {
        int depth = 0;
        int forward = 0;
        int aim = 0;
        for (const string &line: data) {
            vector<string> tokens = aoc::split(line, " ");
            string cmd = tokens[0];
            int steps = stoi(tokens[1]);
            if (cmd == "forward") {
                forward += steps;
                depth += aim * steps;
            } else if (cmd == "up") {
                aim -= steps;
            } else if (cmd == "down") {
                aim += steps;
            } else {
                throw std::runtime_error("Unknown command: " + cmd);
            }
        }
        return depth * forward;
    }
};

int main() {
    S1 s1;
    s1.run_test(150);
    s1.run(1947824);

    S2 s2;
    s2.run_test(900);
    s2.run(1813062561);

    return 0;
}