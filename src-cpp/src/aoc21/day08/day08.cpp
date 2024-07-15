#include <vector>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>
#include <unordered_map>
#include <set>
#include <map>
#include <cmath>

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

// 6 is one of 0, 6, 9
// 5 is one of 2, 3, 5

map<set<char>, int> ENCODING = {
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
            auto digits_out = aoc::split(line, "|")[1];
            std::set<char> letters = {'a', 'b', 'c', 'd', 'e', 'f', 'g'};
            std::unordered_map<char, set<char>> replacements = {
                    {'a', letters},
                    {'b', letters},
                    {'c', letters},
                    {'d', letters},
                    {'e', letters},
                    {'f', letters},
                    {'g', letters},
            };
            auto digits = aoc::split(line, " ");
            // sort from shortest to longest
            sort(digits.begin(), digits.end(), [](const string &a, const string &b) {
                return a.length() < b.length();
            });
            set<char> digit1_letters;
            set<char> digit7_letters;
            set<char> digit4_letters;
            for (const auto &digit_in: digits) {
                auto possible_letters = set<char>(digit_in.begin(), digit_in.end());
                if (digit_in.length() == 2) { // digit 1
                    digit1_letters = possible_letters;
                    for (const auto &letter: "cf") {
                        replacements[letter] = aoc::set_isect(replacements[letter], possible_letters);
                    }
                } else if (digit_in.length() == 3) { // digit 7
                    digit7_letters = possible_letters;
                    replacements['e'] = aoc::set_diff(replacements['e'], digit7_letters);
                    for (const auto &letter: "acf") {
                        replacements[letter] = aoc::set_isect(replacements[letter], possible_letters);
                    }
                    if (!digit1_letters.empty()) {
                        set<char> possible_letters2 = aoc::set_diff(possible_letters, digit1_letters);
                        replacements['a'] = aoc::set_isect(replacements['a'], possible_letters2);
                    }
                } else if (digit_in.length() == 4) {
                    digit4_letters = possible_letters;
                    replacements['e'] = aoc::set_diff(replacements['e'], digit4_letters);
                    for (const auto &letter: "bcdf") { // digit 4
                        replacements[letter] = aoc::set_isect(replacements[letter], possible_letters);
                    }
                    if (!digit7_letters.empty()) {
                        set<char> possible_letters2 = aoc::set_diff(possible_letters, digit7_letters);
                        replacements['b'] = aoc::set_isect(replacements['b'], possible_letters2);
                        replacements['d'] = aoc::set_isect(replacements['d'], possible_letters2);
                    }
                } else if (digit_in.length() == 5) {
                    for (const auto &letter: "adg") { // 2, 3, 5
                        replacements[letter] = aoc::set_isect(replacements[letter], possible_letters);
                    }
                    if (!digit4_letters.empty()) {
                        set<char> possible_letters2 = aoc::set_diff(possible_letters, digit4_letters);
                        replacements['g'] = aoc::set_isect(replacements['g'], possible_letters2);
                    }
                    if (!digit7_letters.empty()) {
                        set<char> possible_letters2 = aoc::set_diff(possible_letters, digit7_letters);
                        replacements['g'] = aoc::set_isect(replacements['g'], possible_letters2);
                    }
                } else if (digit_in.length() == 6) {
                    for (const auto &letter: "abfg") { // 0, 6, 9
                        replacements[letter] = aoc::set_isect(replacements[letter], possible_letters);
                    }
                }
            }

            for (auto &item: replacements) {
                if (item.second.size() > 1) {
                    for (const auto &letter: item.second) {
                        for (const auto &item2: replacements) {
                            if (item2.second.contains(letter) && item2.first != item.first) {
                                item.second.erase(letter);
                            }
                        }
                    }
                }
            }

            map<char, char> replacements2;
            for (const auto &item: replacements) {
                if (item.second.size() > 1) {
                    throw std::runtime_error("Multiple replacements");
                }
                replacements2[(*item.second.begin())] = item.first;
            }

            int counter = 0;
            int decoded_sum = 0;
            auto digits22 = aoc::split(digits_out, " ");
            size_t base = digits22.size() - 1;
            for (const auto &digit_out: digits22) {
                set<char> digits_replaced;
                for (const auto &letter: digit_out) {
                    digits_replaced.insert(replacements2[letter]);
                }
                size_t decoded = ENCODING[digits_replaced];
                decoded_sum += decoded * std::pow(10, (base - counter));
                counter++;

//                cout << ENCODING[digits_replaced];
//                sort(digits_replaced.begin(), digits_replaced.end());
            }
            total += decoded_sum;
//            cout << endl;

//            std::cout << "Input: " << line << std::endl;
//            for (const auto &letter: replacements) {
//                std::cout << letter.first << ": ";
//                if (letter.second.size() > 1) {
//                    std::cout << "multiple ";
//                }
//                for (const auto &letter: letter.second) {
//                    std::cout << letter << " ";
//                }
//                std::cout << std::endl;
//            }
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
    s2.run(973499);

    return 0;
}