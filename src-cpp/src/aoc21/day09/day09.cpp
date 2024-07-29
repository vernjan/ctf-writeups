#include <vector>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>

using namespace std;

typedef vector<vector<int>> matrix;

struct S1 : public StarBase {
    S1() : StarBase(9, 1) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        matrix grid;
        for (const string &line: data) {
            grid.push_back(aoc::split_to_ints(line, ""));
        }

        const size_t height = data.size();
        const size_t width = data[0].size();

        int total = 0;
        for (int i = 0; i < height; ++i) {
            for (int j = 0; j < width; ++j) {
                if (i > 0) {
                    if (grid[i][j] >= grid[i - 1][j]) {
                        continue;
                    }
                }
                if (j < width - 1) {
                    if (grid[i][j] >= grid[i][j + 1]) {
                        continue;
                    }
                }
                if (i < height - 1) {
                    if (grid[i][j] >= grid[i + 1][j]) {
                        continue;
                    }
                }
                if (j > 0) {
                    if (grid[i][j] >= grid[i][j - 1]) {
                        continue;
                    }
                }
                total += grid[i][j] + 1;
            }
        }
        return total;
    }
};

struct S2 : public StarBase {
    S2() : StarBase(9, 2) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        return 0;
    }
};


int main() {
    S1 s1;
    s1.run_test(15);
    s1.run(462);

    S2 s2;
    s2.run_test(1134);
    s2.run(0);

    return 0;
}