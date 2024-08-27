#include <vector>
#include <string>
#include <map>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>

using namespace std;

struct S1 : public StarBase {
    S1() : StarBase(14, 1) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        // naive solution, doesn't scale, ok for 10 rounds
        map<string, string> replacements;
        for (int i = 2; i < data.size(); i++) {
            auto parts = aoc::split(data[i], " -> ");
            replacements[parts[0]] = parts[0][0] + parts[1];
        }

        string polymer = data[0];
        for (int round = 1; round <= 10; round++) {
            string next_polymer{};
            for (int i = 0; i < polymer.size() - 1; i++) {
                next_polymer += replacements[polymer.substr(i, 2)];
            }
            next_polymer += polymer[polymer.size() - 1];
            polymer = next_polymer;
        }

        map<char, int> counts;
        for (const auto &c: polymer) {
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
        // optimized solution, scales very well - idea - count pair (CB, HH) occurrences
        map<string, pair<string, string>> replacements; // pair maps to 2 new pairs
        for (int i = 2; i < data.size(); i++) {
            auto parts = aoc::split(data[i], " -> ");
            replacements[parts[0]] = {parts[0][0] + parts[1], parts[1] + parts[0][1]};
        }

        map<string, size_t> polymer;
        const auto &source_polymer = data[0];
        for (int i = 0; i < source_polymer.size() - 1; i++) {
            polymer[source_polymer.substr(i, 2)]++;
        }

        for (int round = 1; round <= 40; round++) {
            map<string, size_t> next_polymer;
            for (const auto &item: polymer) {
                pair<string, string> &new_pairs = replacements[item.first];
                next_polymer[new_pairs.first] += item.second;
                next_polymer[new_pairs.second] += item.second;
            }
            polymer = std::move(next_polymer);
        }

        map<char, size_t> counts;
        for (const auto &item: polymer) {
            counts[item.first[0]] += item.second;
        }

        counts[source_polymer[source_polymer.size() - 1]]++;

        size_t min = std::numeric_limits<size_t>::max();
        size_t max = 0;
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


int main() {
    S1 s1;
    s1.run_test(1588);
    s1.run(3048);

    S2 s2;
    s2.run_test(2188189693529);
    s2.run(3288891573057);

    return 0;
}