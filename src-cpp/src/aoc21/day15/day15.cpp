#include <vector>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>
#include <deque>
#include <map>

using namespace std;
using namespace aoc;

struct S1 : public StarBase {
    S1() : StarBase(15, 1) {}

    struct path {
        xy head;
        int risk;
    };

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        matrix grid(data);

        xy end_point{static_cast<int>(grid.x_size - 1), static_cast<int>(grid.y_size - 1)};

        map<xy, int> lowest_risks;
        deque<path> paths;// TODO try heap sorted by risk
        paths.push_back({{1, 0}, grid.data[1][0]});
        paths.push_back({{0, 1}, grid.data[0][1]});
        while (!paths.empty()) {
            path current = paths.front();
            paths.pop_front();
            xy &head = current.head;
            if (lowest_risks.contains(head) && lowest_risks[head] <= current.risk) {
                continue;
            }
            lowest_risks[head] = current.risk;
            if (head == end_point) {
                continue;
            }
            for (const xy &neighbor: {xy{head.x + 1, head.y},
                                      xy{head.x, head.y + 1},
                                      xy{head.x - 1, head.y},
                                      xy{head.x, head.y - 1}}) {
                if (0 <= neighbor.x && neighbor.x < grid.x_size && 0 <= neighbor.y && neighbor.y < grid.y_size) {
                    if (lowest_risks.contains(neighbor) && lowest_risks[neighbor] <= current.risk) {
                        continue;
                    }
                    paths.push_back({neighbor, current.risk + grid.data[neighbor.y][neighbor.x]});
                }
            }
        }
        return lowest_risks[end_point];
    }
};

struct S2 : public StarBase {
    S2() : StarBase(15, 2) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        return 0;
    }
};


int main() {
    S1 s1;
    s1.run_test(40);
    s1.run(0);

    S2 s2;
    s2.run_test(0);
    s2.run(0);

    return 0;
}