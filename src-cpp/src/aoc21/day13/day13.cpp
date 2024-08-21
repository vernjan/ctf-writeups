#include <vector>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>

using namespace std;

using grid_t = vector<vector<bool>>;

struct fold_t {
    char axis;
    int value;
};

int fold(const vector<string> &data, bool just_once);

struct S1 : public StarBase {
    S1() : StarBase(13, 1) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        return fold(data, true);
    }
};

struct S2 : public StarBase {
    S2() : StarBase(13, 2) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        return fold(data, false);
    }
};

int fold(const vector<string> &data, bool just_once) {
    int max_x = 0, max_y = 0;
    vector<aoc::xy> points;
    vector<fold_t> folds;
    bool parsing_points = true;
    for (const auto &item: data) {
        if (item.empty()) {
            parsing_points = false;
            continue;
        }
        if (parsing_points) {
            aoc::xy xy = aoc::xy::parse(item);
            points.push_back(xy);
            max_x = std::max(max_x, xy.x);
            max_y = std::max(max_y, xy.y);
        } else {
            vector<string> parts = aoc::split(item, "=");
            char axis = parts[0][11];
            int value = std::stoi(parts[1]);
            folds.push_back({axis, value});
        }
    }

    grid_t grid(max_y + 1, vector<bool>(max_x + 1, false));
    for (const auto &point: points) {
        grid[point.y][point.x] = true;
    }

    int result = 0;
    for (const auto &fold: folds) {
        result = 0;
        if (fold.axis == 'x') {
            for (int y = 0; y <= max_y; ++y) {
                for (int x = 0; x <= max_x / 2; ++x) {
                    if (grid[y][x]) {
                        result++;
                    } else if (grid[y][max_x - x]) {
                        result++;
                        grid[y][x] = true;
                    }
                }
            }
            max_x = max_x / 2 - 1;
        } else {
            for (int y = 0; y <= max_y / 2; ++y) {
                for (int x = 0; x <= max_x; ++x) {
                    if (grid[y][x]) {
                        result++;
                    } else if (grid[max_y - y][x]) {
                        result++;
                        grid[y][x] = true;
                    }
                }
            }
            max_y = max_y / 2 - 1;
        }
        if (just_once) {
            return result;// Star 1
        }
    }

    // print the letters
    for (int y = 0; y <= max_y; ++y) {
        for (int x = 0; x <= max_x; ++x) {
            if (x > 0 && x % 5 == 0) {
                cout << "  ";
            }
            if (grid[y][x]) {
                cout << "#";
            } else {
                cout << ".";
            }
        }
        cout << "\n";
    }
    return result;
}

int main() {
    S1 s1;
    s1.run_test(17);
    s1.run(842);

    S2 s2;
    cout << "\n";
    s2.run_test(16);
    cout << "\n";
    s2.run(95);

    return 0;
}