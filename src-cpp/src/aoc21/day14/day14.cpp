#include <vector>
#include <string>
#include <map>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>

using namespace std;

struct S1 : public StarBase {
    S1() : StarBase(14, 1) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        map<string, string> replacements;
        for (int i = 2; i < data.size(); i++) {
            auto parts = aoc::split(data[i], " -> ");
            replacements[parts[0]] = parts[0][0] + parts[1];
        }

        string prev_polymer = data[0];
        for (int round = 1; round <= 20; round++) {
            string polymer{};
            for (int i = 0; i < prev_polymer.size() - 1; i++) {
                polymer += replacements[prev_polymer.substr(i, 2)];
            }
            polymer += prev_polymer[prev_polymer.size() - 1];
//            cout << polymer << endl;
            map<char, int> counts;
            for (const auto &c: prev_polymer) {
                counts[c]++;
            }

            cout << "Round " << round << endl;
            for (const auto &item: counts) {
                cout << item.first << ": " << item.second << endl;
            }
            cout << endl;

            prev_polymer = polymer;
        }

        map<char, int> counts;
        for (const auto &c: prev_polymer) {
            counts[c]++;
        }

        int min = std::numeric_limits<int>::max();
        int max = 0;
        for (const auto &item: counts) {
            if (item.second < min) {
                min = item.second;
            }
            if (item.second > max) {
                max = item.second;
            }
        }

        return max - min;
    }
};

struct S2 : public StarBase {
    S2() : StarBase(14, 2) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        return 0;
    }
};


int main() {
    S1 s1;
    s1.run_test(1588);
    s1.run(3048);

    S2 s2;
    s2.run_test(2188189693529);
    s2.run(0);

    return 0;
}