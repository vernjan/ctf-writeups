#include "aoc/aoc_utils.h"
#include <chrono>
#include <sstream>
#include <iomanip>

namespace aoc {

    int btoi(const string &binary) {
        return std::stoi(binary, nullptr, 2);
    }

    string add_leading_zeroes(int value, int precision) {
        std::ostringstream oss;
        oss << std::setw(precision) << std::setfill('0') << value;
        return oss.str();
    }

    void ltrim(string &s) {
        auto first_non_space = std::find_if(s.begin(), s.end(), [](unsigned char ch) {
            return !std::isspace(ch);
        });
        s.erase(s.begin(), first_non_space);
    }

    void rtrim(string &s) {
        auto last_non_space = std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
            return !std::isspace(ch);
        }).base();
        s.erase(last_non_space, s.end());
    }

    void trim(string &s) {
        ltrim(s);
        rtrim(s);
    }

    [[nodiscard]] set<char> set_isect(const set<char> &a, const set<char> &b) {
        set<char> intersection;
        std::set_intersection(a.begin(), a.end(), b.begin(), b.end(),
                              std::inserter(intersection, intersection.begin()));
        return intersection;
    }

    [[nodiscard]] set<char> set_diff(const set<char> &a, const set<char> &b) {
        set<char> diff;
        std::set_difference(a.begin(), a.end(), b.begin(), b.end(),
                            std::inserter(diff, diff.begin()));
        return diff;
    }


}// namespace aoc