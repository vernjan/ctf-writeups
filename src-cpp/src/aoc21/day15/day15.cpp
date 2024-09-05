#include <vector>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>
#include <map>
#include <queue>

using namespace std;
using namespace aoc;


size_t calc_min_risk(const matrix &grid);

struct S1 : public StarBase {
    S1() : StarBase(15, 1) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        return calc_min_risk(matrix{data});
    }
};

struct S2 : public StarBase {
    S2() : StarBase(15, 2) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        vector<string> data_x5;
        for (int i = 0; i < 5; ++i) {
            for (const string &line: data) {
                string line_x5{};
                for (int j = 0; j < 5; ++j) {

                    line_x5 += line;
                }
                data_x5.push_back(line_x5);
            }
        }
        return calc_min_risk(matrix{data_x5});
    }
};

struct path {
    xy head;
    int risk;

    bool operator<(const path &rhs) const {
        return risk > rhs.risk;
    }
};

size_t calc_min_risk(const matrix &grid) {
    xy end_point{static_cast<int>(grid.x_size - 1), static_cast<int>(grid.y_size - 1)};

    map<xy, int> lowest_risks;
    priority_queue<path> paths;
    paths.emplace(xy{1, 0}, grid.data[1][0]);
    paths.emplace(xy{0, 1}, grid.data[0][1]);
    while (!paths.empty()) {
        path current = paths.top();
        paths.pop();
        xy &head = current.head;
        if (lowest_risks.contains(head) && lowest_risks[head] <= current.risk) {
            continue;
        }
        lowest_risks[head] = current.risk;
        if (head == end_point) {
            return current.risk;
//                            continue;
        }
        for (const xy &neighbor: {xy{head.x + 1, head.y},
                                  xy{head.x, head.y + 1},
                                  xy{head.x - 1, head.y},
                                  xy{head.x, head.y - 1}}) {
            if (0 <= neighbor.x && neighbor.x < grid.x_size && 0 <= neighbor.y && neighbor.y < grid.y_size) {
                //                    if (lowest_risks.contains(neighbor) && lowest_risks[neighbor] <= current.risk) {
                //                        continue;
                //                    }
                paths.emplace(neighbor, current.risk + grid.data[neighbor.y][neighbor.x]);
            }
        }
    }
//            return lowest_risks[end_point];
    return 0;
}


int main() {
    S1 s1;
    s1.run_test(40);
    s1.run(388);

    S2 s2;
    s2.run_test(315);
    s2.run(0);

    return 0;
}