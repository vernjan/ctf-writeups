#include <vector>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>
#include <cmath>
#include <map>
#include <set>

using namespace std;

// 0 = 6 = 01110111 = abcefg
// 1 = 2 = 00010010 = cf        U
// 2 = 5 = 01011101 = acdeg
// 3 = 5 = 01011011 = acdfg
// 4 = 4 = 00111010 = bcdf      U
// 5 = 5 = 01101011 = abdfg
// 6 = 6 = 01101111 = abdefg
// 7 = 3 = 01010010 = acf       U
// 8 = 7 = 01111111 = abcdefg   U
// 9 = 6 = 01111011 = abcdfg

map<set<char>, int> SEVEN_SEGMENT_DISPLAY = {
        {{'a', 'b', 'c', 'e', 'f', 'g'}, 0},
        {{'c', 'f'}, 1},
        {{'a', 'c', 'd', 'e', 'g'}, 2},
        {{'a', 'c', 'd', 'f', 'g'}, 3},
        {{'b', 'c', 'd', 'f'}, 4},
        {{'a', 'b', 'd', 'f', 'g'}, 5},
        {{'a', 'b', 'd', 'e', 'f', 'g'}, 6},
        {{'a', 'c', 'f'}, 7},
        {{'a', 'b', 'c', 'd', 'e', 'f', 'g'}, 8},
        {{'a', 'b', 'c', 'd', 'f', 'g'}, 9},
};

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

            auto digits_in = aoc::split(aoc::split(line, "|")[0], " ");
            auto digits_out = aoc::split(aoc::split(line, "|")[1], " ");

            std::map<char, set<char>> wiring = {
                    {'a', {'a', 'b', 'c', 'd', 'e', 'f', 'g'}},
                    {'b', {'a', 'b', 'c', 'd', 'e', 'f', 'g'}},
                    {'c', {'a', 'b', 'c', 'd', 'e', 'f', 'g'}},
                    {'d', {'a', 'b', 'c', 'd', 'e', 'f', 'g'}},
                    {'e', {'a', 'b', 'c', 'd', 'e', 'f', 'g'}},
                    {'f', {'a', 'b', 'c', 'd', 'e', 'f', 'g'}},
                    {'g', {'a', 'b', 'c', 'd', 'e', 'f', 'g'}},
            };

            // sort digits from shortest to longest
            sort(digits_in.begin(), digits_in.end(), [](const string &a, const string &b) {
                return a.length() < b.length();
            });

            set<char> digit1_letters;
            set<char> digit7_letters;
            set<char> digit4_letters;
            for (const auto &digit_in: digits_in) {
                const auto possible_letters = set<char>(digit_in.begin(), digit_in.end());
                if (digit_in.length() == 2) {// digit 1
                    digit1_letters = possible_letters;
                    update_wiring(wiring, "cf", possible_letters);
                } else if (digit_in.length() == 3) {// digit 7
                    digit7_letters = possible_letters;
                    wiring['e'] = aoc::set_diff(wiring['e'], digit7_letters);
                    update_wiring(wiring, "acf", possible_letters);
                    if (!digit1_letters.empty()) {
                        set<char> possible_letters2 = aoc::set_diff(possible_letters, digit1_letters);
                        wiring['a'] = aoc::set_isect(wiring['a'], possible_letters2);
                    }
                } else if (digit_in.length() == 4) {// digit 4
                    digit4_letters = possible_letters;
                    wiring['e'] = aoc::set_diff(wiring['e'], digit4_letters);
                    update_wiring(wiring, "bcdf", possible_letters);
                    if (!digit7_letters.empty()) {
                        set<char> possible_letters2 = aoc::set_diff(possible_letters, digit7_letters);
                        wiring['b'] = aoc::set_isect(wiring['b'], possible_letters2);
                        wiring['d'] = aoc::set_isect(wiring['d'], possible_letters2);
                    }
                } else if (digit_in.length() == 5) {// digits 2, 3, 5
                    update_wiring(wiring, "adg", possible_letters);
                    if (!digit4_letters.empty()) {
                        set<char> possible_letters2 = aoc::set_diff(possible_letters, digit4_letters);
                        wiring['g'] = aoc::set_isect(wiring['g'], possible_letters2);
                    }
                    if (!digit7_letters.empty()) {
                        set<char> possible_letters2 = aoc::set_diff(possible_letters, digit7_letters);
                        wiring['g'] = aoc::set_isect(wiring['g'], possible_letters2);
                    }
                } else if (digit_in.length() == 6) {// digits 0, 6, 9
                    update_wiring(wiring, "abfg", possible_letters);
                }
            }

            for (auto &item: wiring) {
                if (item.second.size() > 1) {
                    for (const auto &letter: item.second) {
                        for (const auto &item2: wiring) {
                            if (item2.second.contains(letter) && item.first != item2.first) {
                                item.second.erase(letter);
                            }
                        }
                    }
                }
            }

            map<char, char> wiring_reversed;
            for (const auto &item: wiring) {
                if (item.second.size() > 1) {
                    throw std::runtime_error("Multiple replacements");
                }
                wiring_reversed[(*item.second.begin())] = item.first;
            }

            for (int i = 0; i < digits_out.size(); ++i) {
                set<char> digit_out_letters_rewired;
                for (const auto &letter: digits_out[i]) {
                    digit_out_letters_rewired.insert(wiring_reversed[letter]);
                }
                size_t digit_out = SEVEN_SEGMENT_DISPLAY[digit_out_letters_rewired];
                total += digit_out * std::pow(10, (digits_out.size() - 1 - i));
            }
        }
        return total;
    }

    static void update_wiring(map<char, set<char>> &wiring, const string &letters, const set<char> &possible_letters) {
        for (const auto &letter: letters) {
            wiring[letter] = aoc::set_isect(wiring[letter], possible_letters);
        }
    }
};

int main() {
    S1 s1;
    s1.run_test(26);
    s1.run(284);

    S2 s2;
    s2.run_test(61229);
    s2.run(973499);

    return 0;
}