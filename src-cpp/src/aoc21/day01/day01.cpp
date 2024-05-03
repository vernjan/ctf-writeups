#include <iostream>
#include <vector>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>

using namespace std;

struct S1 : public StarBase {
    S1() : StarBase(1, 1) {}

    [[nodiscard]] int execute(const vector<string> &data) const override {
        int total = 0;
        int prev_depth = -1;
        for (const string &line: data) {
            int depth = stoi(line);
            if (prev_depth != -1 && depth > prev_depth) {
                total++;
            }
            prev_depth = depth;
        }
        return total;
    }
};

struct S2 : public StarBase {
    S2() : StarBase(1, 2) {}

    [[nodiscard]] int execute(const vector<string> &data) const override {
        int total = 0;
        vector<int> depths;
        for (const string &line: data) {
            int depth = stoi(line);
            if (depths.size() == 3) {
                int prev_window = depths[0] + depths[1] + depths[2];
                int window = depths[1] + depths[2] + depth;
                if (window > prev_window) {
                    total++;
                }
                depths.erase(depths.begin());
            }
            depths.push_back(depth);
        }
        return total;
    }
};

int main() {
    S1 s1;
    s1.run_test(7);
    s1.run(1655);

    S2 s2;
    s2.run_test(5);
    s2.run(1683);

    return 0;
}