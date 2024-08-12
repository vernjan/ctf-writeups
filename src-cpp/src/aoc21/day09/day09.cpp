#include <set>
#include <vector>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>

using namespace std;

struct S1 : public StarBase {
    S1() : StarBase(9, 1) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        aoc::matrix grid(data);

        int total = 0;
        for (int y = 0; y < grid.y_size; ++y) {
            for (int x = 0; x < grid.x_size; ++x) {
                if (y > 0) {
                    if (grid.data[y][x] >= grid.data[y - 1][x]) {
                        continue;
                    }
                }
                if (x < grid.x_size - 1) {
                    if (grid.data[y][x] >= grid.data[y][x + 1]) {
                        continue;
                    }
                }
                if (y < grid.y_size - 1) {
                    if (grid.data[y][x] >= grid.data[y + 1][x]) {
                        continue;
                    }
                }
                if (x > 0) {
                    if (grid.data[y][x] >= grid.data[y][x - 1]) {
                        continue;
                    }
                }
                total += grid.data[y][x] + 1;
            }
        }
        return total;
    }
};

struct S2 : public StarBase {
    S2() : StarBase(9, 2) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        aoc::matrix grid(data);

        set<aoc::xy> visited;
        vector<int> pool_sizes;
        for (int y = 0; y < grid.y_size; ++y) {
            for (int x = 0; x < grid.x_size; ++x) {
                int value = grid.data[y][x];
                if (value == 9) {
                    continue;
                }
                // BFS
                aoc::xy start_point{y, x};
                vector<aoc::xy> queue;
                set<aoc::xy> pool;
                queue.push_back(start_point);
                while (!queue.empty()) {
                    aoc::xy current = queue.back();
                    queue.pop_back();
                    if (visited.contains(current)) {
                        continue;
                    }
                    pool.insert(current);
                    visited.insert(current);
                    if (current.x > 0 && grid.data[current.x - 1][current.y] != 9) {
                        queue.emplace_back(current.x - 1, current.y);
                    }
                    if (current.y < grid.x_size - 1 && grid.data[current.x][current.y + 1] != 9) {
                        queue.emplace_back(current.x, current.y + 1);
                    }
                    if (current.x < grid.y_size - 1 && grid.data[current.x + 1][current.y] != 9) {
                        queue.emplace_back(current.x + 1, current.y);
                    }
                    if (current.y > 0 && grid.data[current.x][current.y - 1] != 9) {
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