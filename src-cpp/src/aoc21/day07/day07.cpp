#include <vector>
#include <limits>
#include <cmath>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>

using namespace std;

size_t calc_fuel(vector<int> &crabs, int pos, int(*calc)(int dist)) {
    int fuel = 0;
    for (auto crab: crabs) {
        fuel += calc(abs(pos - crab));
    }
    return fuel;
}

size_t calc_min_fuel_bf(vector<int> &crabs, int min, int max, int(*calc)(int dist)) {
    size_t min_fuel = numeric_limits<size_t>::max();
    for (int i = min; i <= max; i++) {
        size_t fuel = calc_fuel(crabs, i, calc);
        //cout << "Fuel[ " << i << "]: " << fuel << "\n";
        if (fuel < min_fuel) {
            min_fuel = fuel;
        }
    }
    return min_fuel;
}


struct S1 : public StarBase {
    S1() : StarBase(7, 1) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        vector<int> crabs = aoc::split_to_ints(data[0], ",");

        // Option 1 - Brute force:
//        const auto [min, max] = minmax_element(begin(crabs), end(crabs));
//        return calc_min_fuel_bf(crabs, *min, *max, [](int dist) { return dist; });

        // Option 2 - Find median:
        std::sort(begin(crabs), end(crabs));
        int median = crabs[crabs.size() / 2];
        return calc_min_fuel_bf(crabs, median - 1, median + 1, [](int dist) { return dist; });
    }
};

struct S2 : public StarBase {
    S2() : StarBase(7, 2) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        vector<int> crabs = aoc::split_to_ints(data[0], ",");

        // Option 1 - Brute force:
//        const auto [min, max] = minmax_element(begin(crabs), end(crabs));
//        return calc_min_fuel_bf(crabs, *min, *max, [](int dist) { return dist * (dist + 1) / 2; });

        // Option 2 - Find average:
        int sum = 0;
        for (auto crab: crabs) {
            sum += crab;
        }
        int avg = (int) round(sum / crabs.size());
        return calc_min_fuel_bf(crabs, avg - 1, avg + 1, [](int dist) { return dist * (dist + 1) / 2; });
    }
};


int main() {
    S1 s1;
    s1.run_test(37);
    s1.run(343441);

    S2 s2;
    s2.run_test(168);
    s2.run(98925151);

    return 0;
}