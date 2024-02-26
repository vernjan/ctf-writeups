#include <iostream>
#include <vector>

#include <aoc/StarBase.h>

using namespace std;

struct Day02S1 : public StarBase {
    Day02S1() : StarBase(2, 1) {}

    [[nodiscard]] int execute(const vector<string> &data) const override {
        int depth = 0;
        int forward = 0;
        for (const string &line: data) {
            vector<string> tokens = split(line, " ");
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

struct Day02S2 : public StarBase {
    Day02S2() : StarBase(1, 2) {}

    [[nodiscard]] int execute(const vector<string> &data) const override {
        int total = 0;
        // TBD
        return total;
    }
};

int main() {
    Day02S1 dayS1;
    dayS1.run_test(150);
    dayS1.run(1947824);

    //    Day02S2 dayS2;
    //    dayS2.run_test(5);
    //    dayS2.run(1683);

    return 0;
}