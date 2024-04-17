#include <vector>

#include <aoc/StarBase.h>

using namespace std;

struct S1 : public StarBase {
    S1() : StarBase(0, 1) {}

    [[nodiscard]] int execute(const vector<string> &data) const override {
        return 0;
    }
};

struct S2 : public StarBase {
    S2() : StarBase(0, 2) {}

    [[nodiscard]] int execute(const vector<string> &data) const override {
        return 0;
    }
};


int main() {
    S1 s1;
    s1.run_test(0);
    s1.run(0);

    S2 s2;
    s2.run_test(0);
    s2.run(0);

    return 0;
}