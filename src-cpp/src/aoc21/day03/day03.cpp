#include <cmath>
#include <vector>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>

using namespace std;

enum class Rating {
    O2,
    CO2
};

string find_rating(Rating rating, const vector<string> &data, int position);

struct S1 : public StarBase {
    S1() : StarBase(3, 1) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        size_t total_numbers = data.size();
        size_t digits = data[0].size();
        int gamma_rate = 0;
        for (size_t i = 0; i < digits; i++) {
            int zeroes = 0;
            for (const string &line: data) {
                if (line[digits - 1 - i] == '0') {
                    zeroes++;
                }
            }
            if (zeroes < total_numbers / 2) {
                gamma_rate += pow(2, i);
            }
        }
        int epsilon_rate = pow(2, digits) - 1 - gamma_rate;
        return gamma_rate * epsilon_rate;
    }
};

struct S2 : public StarBase {
    S2() : StarBase(3, 2) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        int o2_rate = aoc::btoi(find_rating(Rating::O2, data, 0));
        int co2_rate = aoc::btoi(find_rating(Rating::CO2, data, 0));
        return o2_rate * co2_rate;
    }
};

string find_rating(Rating rating, const vector<string> &data, int position) {
    if (data.size() == 1) {
        return data[0];
    }
    vector<string> zeroes;
    vector<string> ones;
    for (const string &line: data) {
        if (line[position] == '0') {
            zeroes.push_back(line);
        } else {
            ones.push_back(line);
        }
    }
    switch (rating) {
        case Rating::O2:
            if (ones.size() >= zeroes.size()) {
                return find_rating(rating, ones, position + 1);
            }
            return find_rating(rating, zeroes, position + 1);
        case Rating::CO2:
            if (zeroes.size() <= ones.size()) {
                return find_rating(rating, zeroes, position + 1);
            }
            return find_rating(rating, ones, position + 1);
    }
}

int main() {
    S1 s1;
    s1.run_test(198);
    s1.run(3009600);

    S2 s2;
    s2.run_test(230);
    s2.run(6940518);

    return 0;
}