#include <set>
#include <vector>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>

using namespace std;

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
        matrix grid;
        for (const string &line: data) {
            grid.push_back(aoc::split_to_ints(line, ""));
        }

        const size_t height = data.size();
        const size_t width = data[0].size();

        set<aoc::point> visited;
        vector<int> pool_sizes;
        for (int i = 0; i < height; ++i) {
            for (int j = 0; j < width; ++j) {
                int value = grid[i][j];
                if (value == 9) {
                    continue;
                }
                // BFS
                aoc::point start_point{i, j};
                vector<aoc::point> queue;
                set<aoc::point> pool;
                queue.push_back(start_point);
                while (!queue.empty()) {
                    aoc::point current = queue.back();
                    queue.pop_back();
                    if (visited.contains(current)) {
                        continue;
                    }
                    pool.insert(current);
                    visited.insert(current);
                    if (current.x > 0 && grid[current.x - 1][current.y] != 9) {
                        queue.emplace_back(current.x - 1, current.y);
                    }
                    if (current.y < width - 1 && grid[current.x][current.y + 1] != 9) {
                        queue.emplace_back(current.x, current.y + 1);
                    }
                    if (current.x < height - 1 && grid[current.x + 1][current.y] != 9) {
                        queue.emplace_back(current.x + 1, current.y);
                    }
                    if (current.y > 0 && grid[current.x][current.y - 1] != 9) {
                        queue.emplace_back(current.x, current.y - 1);
                    }
                }
                if (!pool.empty()) {
                    pool_sizes.push_back(pool.size());
                }
            }
        }
        std::sort(pool_sizes.begin(), pool_sizes.end(), std::greater<>());
        return pool_sizes[0] * pool_sizes[1] * pool_sizes[2];
    }
};


int main() {
    S1 s1;
    s1.run_test(15);
    s1.run(462);

    S2 s2;
    s2.run_test(1134);
    s2.run(1397760);

    return 0;
}