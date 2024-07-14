#include <vector>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>
#include <unordered_map>

using namespace std;

// 0 = 6 = 01110111
// 1 = 2 = 00010010 U
// 2 = 5 = 01011101
// 3 = 5 = 01011011
// 4 = 4 = 00111010 U
// 5 = 5 = 01101011
// 6 = 6 = 01101111
// 7 = 3 = 01010010 U
// 8 = 7 = 01111111 U
// 9 = 6 = 01111011

// 6 is one of 0, 6, 9
// 5 is one of 2, 3, 5

struct S1 : public StarBase {
    S1() : StarBase(8, 1) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        size_t total = 0;
        for (auto &line: data) {
            string output = aoc::split(line, "|")[1];
            for (const auto &digit: aoc::split(output, " ")) {
                if ((digit.length() >= 2 && digit.length() <= 4) || digit.length() == 7) {
                    total++;
                }
            }
        }
        return total;
    }
};

struct S2 : public StarBase {
    S2() : StarBase(8, 2) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        size_t total = 0;

        for (auto &line: data) {
            auto input_output = aoc::split(line, "|");
            string input = input_output[0];
            string output = input_output[1];
            std::unordered_map<char, char> replacements = {};
            for (const auto &digit: aoc::split(output, " ")) {
                if ((digit.length() >= 2 && digit.length() <= 4) || digit.length() == 7) {

                    total++;
                }
            }
        }
        return total;
    }
};


int main() {
    S1 s1;
    s1.run_test(26);
    s1.run(284);

    S2 s2;
    s2.run_test(61229);
    s2.run(0);

    return 0;
}