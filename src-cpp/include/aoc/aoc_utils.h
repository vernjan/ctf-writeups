#pragma once

#include <ostream>
#include <set>
#include <string>
#include <utility>
#include <vector>

using std::vector, std::string, std::set;

namespace aoc {

    /*
     * Binary to integer
     */
    int btoi(const string &binary);

    string add_leading_zeroes(int value, int precision);

    // left trim
    void ltrim(string &s);

    // right trim
    void rtrim(string &s);

    // trim from both ends
    void trim(string &s);

    template<typename T>
    vector<T> split(string text, const string &delimiter, T (*convert)(const string &)) {
        vector<T> tokens;
        size_t pos;
        string token;
        while (!text.empty() && (pos = text.find(delimiter)) != string::npos) {
            pos = std::max(pos, (size_t) 1);
            token = text.substr(0, pos);
            aoc::trim(token);
            if (!token.empty()) {
                tokens.push_back(convert(token));
            }
            text.erase(0, pos + delimiter.length());
        }
        aoc::trim(text);
        if (!text.empty()) {
            tokens.push_back(convert(text));
        }
        return tokens;
    }

    // inline https://stackoverflow.com/questions/4445654/multiple-definition-of-template-specialization-when-using-different-objects
    inline vector<string> split(string text, const string &delimiter) {
        return aoc::split<string>(std::move(text), delimiter, [](const string &s) { return s; });
    }

    inline vector<int> split_to_ints(string text, const string &delimiter) {
        return split<int>(std::move(text), delimiter, [](const string &s) { return std::stoi(s); });
    }

    // signum
    template<typename T>
    int sgn(T val) {
        return (T(0) < val) - (val < T(0));
    }

    struct matrix {
        vector<vector<int>> data;
        const size_t y_size;
        const size_t x_size;

        explicit matrix(const vector<string> &data) : y_size(data.size()), x_size(data[0].size()) {
            for (const string &line: data) {
                this->data.push_back(aoc::split_to_ints(line, ""));
            }
        }
    };

    struct xy {
        const int x;
        const int y;

        static xy parse(const string &text) {
            vector<int> xy = aoc::split_to_ints(text, ",");
            return {xy[0], xy[1]};
        }

        inline bool operator==(const xy &rhs) const {
            return x == rhs.x && y == rhs.y;
        }

        inline bool operator<(const xy &rhs) const {
            return x < rhs.x || (x == rhs.x && y < rhs.y);
        }
    };

    [[nodiscard]] set<char> set_isect(const set<char> &a, const set<char> &b);

    [[nodiscard]] set<char> set_diff(const set<char> &a, const set<char> &b);


}// namespace aoc
