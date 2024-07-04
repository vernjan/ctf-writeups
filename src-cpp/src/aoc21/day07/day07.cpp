#include <vector>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>

using namespace std;

struct S1 : public StarBase {
    S1() : StarBase(7, 1) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        vector<int> crabs = aoc::split_to_ints(data[0], ",");
        const auto [min, max] = std::minmax_element(begin(crabs), end(crabs));
        cout << "Min: " << *min << ", max: " << *max << "\n";

        int min_fuel = INT_MAX;
        // TODO Optimize?
        for (int i = *min; i <= *max; i++) {
            int fuel = 0;
            for (auto crab: crabs) {
                fuel += std::abs(i - crab);
            }
            //            cout << "Fuel[" << i << "]: " << fuel << "\n";
            if (fuel < min_fuel) {
                min_fuel = fuel;
            }
        }

        return min_fuel;
    }
};

struct S2 : public StarBase {
    S2() : StarBase(7, 2) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        return 0;
    }
};


int main() {
    S1 s1;
    s1.run_test(37);
    s1.run(343441);

    S2 s2;
    s2.run_test(168);
    s2.run(0);

    return 0;
}