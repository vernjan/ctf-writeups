#include <vector>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>

using namespace std;

size_t run_simulation(const vector<string> &data, size_t rounds);

struct S1 : public StarBase {
    S1() : StarBase(11, 1) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        return run_simulation(data, 100);//total number of flashes
    }
};

struct S2 : public StarBase {
    S2() : StarBase(11, 2) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        return run_simulation(data, numeric_limits<int>::max());//the round when all octopuses flash
    }
};

size_t run_simulation(const vector<string> &data, size_t rounds) {
    aoc::matrix grid(data);
    int total = 0;
    for (int round = 0; round < rounds; ++round) {
        set<aoc::xy> flashes;
        for (int y = 0; y < grid.y_size; ++y) {
            for (int x = 0; x < grid.x_size; ++x) {
                if (grid.data[y][x] == 9) {//will flash this round
                    flashes.emplace(x, y);
                } else if (grid.data[y][x] == -1) {// flashed last round
                    grid.data[y][x] = 1;
                } else {
                    grid.data[y][x]++;
                }
            }
        }

        int round_total = 0;
        while (!flashes.empty()) {
            auto flash_iter = flashes.begin();
            aoc::xy flash = *flash_iter;
            flashes.erase(flash_iter);
            grid.data[flash.y][flash.x] = -1;
            round_total++;
            for (int y = flash.y - 1; y <= flash.y + 1; ++y) {
                for (int x = flash.x - 1; x <= flash.x + 1; ++x) {
                    if (y < 0 || y >= grid.y_size || x < 0 || x >= grid.x_size) {
                        continue;
                    }
                    if (grid.data[y][x] == 9) {
                        flashes.emplace(x, y);
                    } else if (grid.data[y][x] != -1) {
                        grid.data[y][x]++;
                    }
                }
            }
        }
        if (round_total == grid.x_size * grid.y_size) {
            return round + 1;// Star 2
        }
        total += round_total;
    }
    return total;// Star 1
}

int main() {
    S1 s1;
    s1.run_test(1656);
    s1.run(1585);

    S2 s2;
    s2.run_test(195);
    s2.run(382);

    return 0;
}