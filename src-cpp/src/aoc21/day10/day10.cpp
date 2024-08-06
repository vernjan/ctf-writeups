#include <map>
#include <vector>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>

using namespace std;

const map<char, int> POINTS_S1 = {
        {')', 3},
        {']', 57},
        {'}', 1197},
        {'>', 25137},
};

const map<char, int> POINTS_S2 = {
        {'(', 1},
        {'[', 2},
        {'{', 3},
        {'<', 4},
};

const map<char, int> BRACKETS = {
        // ASCII diff between the opening and closing bracket
        {'(', 1},
        {'[', 2},
        {'{', 2},
        {'<', 2},
};

struct LineResult {
    bool corrupted;
    char bracket;
};

LineResult evaluate_brackets(const string &brackets, vector<char> &stack);


struct S1 : public StarBase {
    S1() : StarBase(10, 1) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        size_t total = 0;
        for (const string &brackets: data) {
            vector<char> stack;
            LineResult line_result = evaluate_brackets(brackets, stack);
            if (line_result.corrupted) {
                total += POINTS_S1.at(line_result.bracket);
            }
        }
        return total;
    }
};


struct S2 : public StarBase {
    S2() : StarBase(10, 2) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        vector<size_t> sub_totals;
        for (const string &brackets: data) {
            vector<char> stack;
            LineResult line_result = evaluate_brackets(brackets, stack);
            if (!line_result.corrupted) {
                size_t sub_total = 0;
                while (!stack.empty()) {
                    char open_bracket = stack.back();
                    stack.pop_back();
                    sub_total = (sub_total * 5) + POINTS_S2.at(open_bracket);
                }
                sub_totals.push_back(sub_total);
            }
        }
        sort(sub_totals.begin(), sub_totals.end());
        return sub_totals[sub_totals.size() / 2];
    }
};

LineResult evaluate_brackets(const string &brackets, vector<char> &stack) {
    for (const char &bracket: brackets) {
        if (BRACKETS.contains(bracket)) {
            stack.push_back(bracket);
        } else {
            char open_bracket = stack.back();
            stack.pop_back();
            if (bracket != open_bracket + BRACKETS.at(open_bracket)) {
                return LineResult{true, bracket};
            }
        }
    }
    return LineResult{false, 0};
}


int main() {
    S1 s1;
    s1.run_test(26397);
    s1.run(319329);

    S2 s2;
    s2.run_test(288957);
    s2.run(3515583998);

    return 0;
}