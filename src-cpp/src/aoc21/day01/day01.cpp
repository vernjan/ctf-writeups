#include <iostream>
#include <vector>

#include <aoc/StarBase.h>

// TODO Unit tests
// TODO Run framework - reading from file, timing

using namespace std;


struct Day01 : StarBase {
    explicit Day01(const string &input_file) : StarBase(input_file) {}

    [[nodiscard]] int star1() const override {
        int total = 0;
        int prev_depth = -1;
        for (const string &line: this->lines) {
            int depth = stoi(line);
            if (prev_depth != -1 && depth > prev_depth) {
                total++;
            }
            prev_depth = depth;
        }
        return total;
    }

    [[nodiscard]] int star2() const override {
        int total = 0;
        vector<int> depths;
        for (const string &line: lines) {
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
    Day01 day("aoc21/day01/input.txt");
    cout << "Star 1: " << day.star1() << "\n";
    cout << "Star 2: " << day.star2() << "\n";

    // Star 1: 1655
    // Star 2: 1683

    return 0;
}