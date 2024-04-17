#include <vector>

#include <aoc/StarBase.h>

using namespace std;

const int BOARD_SIZE = 1000;

int countOverlaps(const vector<string> &data, bool include_diagonals);

struct S1 : public StarBase {
    S1() : StarBase(5, 1) {}

    [[nodiscard]] int execute(const vector<string> &data) const override {
        return countOverlaps(data, false);
    }
};

struct S2 : public StarBase {
    S2() : StarBase(5, 2) {}

    [[nodiscard]] int execute(const vector<string> &data) const override {
        return countOverlaps(data, true);
    }
};


int countOverlaps(const vector<string> &data, bool include_diagonals) {
    uint8_t board[BOARD_SIZE][BOARD_SIZE]{};
    int total = 0;

    for (const string &line: data) {
        vector<string> coords = split(line, "->");
        vector<int> coord1 = split_to_ints(coords[0], ",");// TODO coord class?
        vector<int> coord2 = split_to_ints(coords[1], ",");
        int x1 = coord1[0];
        int x2 = coord2[0];
        int y1 = coord1[1];
        int y2 = coord2[1];

        if (x1 == x2) {// vertical
            if (y1 > y2) {
                swap(y1, y2);
            }
            for (int y = y1; y <= y2; y++) {
                board[x1][y] += 1;
                if (board[x1][y] == 2) {
                    total++;
                }
            }
        } else if (y1 == y2) {// horizontal
            if (x1 > x2) {
                swap(x1, x2);
            }
            for (int x = x1; x <= x2; x++) {
                board[x][y1] += 1;
                if (board[x][y1] == 2) {
                    total++;
                }
            }
        } else if (include_diagonals) {
            // TODO
        }
    }

    return total;
}

int main() {
    S1 s1;
    s1.run_test(5);
    s1.run(5306);

    S2 s2;
    s2.run_test(12);
    s2.run(0);

    return 0;
}