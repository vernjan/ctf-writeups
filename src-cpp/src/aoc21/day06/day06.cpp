#include <vector>
#include <map>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>

using namespace std;

ulong count_fish(const vector<string> &data, const int days);

struct S1 : public StarBase {
    S1() : StarBase(6, 1) {}

    [[nodiscard]] ulong execute(const vector<string> &data) const override {
        return count_fish(data, 80);

    }
};

struct S2 : public StarBase {
    S2() : StarBase(6, 2) {}

    [[nodiscard]] ulong execute(const vector<string> &data) const override {
        return count_fish(data, 256);
    }
};

ulong count_fish(const vector<string> &data, const int days) {
    // TODO Better way how to initialize this?
    map<int, ulong> fish_counts;
    for (int i = 0; i < 9; ++i) {
        fish_counts[i] = 0;
    }

    vector<int> fish = aoc::split_to_ints(data[0], ",");
    for (int f: fish) {
        fish_counts[f]++;
    }

    for (int i = 0; i < days; ++i) {
//            for (const auto &pair: fish_counts) {
//                std::cout << pair.first << ":" << pair.second << ", ";
//            }
//            std::cout << "\n";

        ulong newborns = fish_counts[0];

        for (int j = 0; j < 6; ++j) {
            fish_counts[j] = fish_counts[j + 1];
        }

        fish_counts[6] = fish_counts[7] + newborns;
        fish_counts[7] = fish_counts[8];
        fish_counts[8] = newborns;
    }

    // TODO Better way how to sum this?
    ulong total = 0;
    for (const auto &pair: fish_counts) {
        total += pair.second;
    }
    return total;
}


int main() {
    S1 s1;
    s1.run_test(5934);
    s1.run(362346);

    S2 s2;
    s2.run_test(26984457539);
    s2.run(1639643057051);

    return 0;
}