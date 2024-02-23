#include <fstream>
#include <iostream>
#include <vector>

using namespace std;

int main() {
        ifstream input_file("../aoc21/day01/input.txt");
//    ifstream input_file("../aoc21/day01/input-test.txt");

    if (!input_file.is_open()) {
        cout << "Could not open the file" << endl;
        return 1;
    }

    vector<string> lines;
    string line;
    while (getline(input_file, line)) {
        lines.push_back(line);
    }

    int total = 0;
    int prev_depth = -1;
    for (string &l: lines) {
        int depth = stoi(l);
        if (prev_depth != -1 && depth > prev_depth) {
            total++;
        }
        prev_depth = depth;
    }

    cout << "Total: " << total << "\n";

    // Star 1: 1655
    // Star 2: TBD

    return 0;
};