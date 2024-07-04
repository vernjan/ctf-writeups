#include <array>
#include <vector>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>

using namespace std;

// Bingo board
struct Board {
    array<int, 25> numbers{}; // 5x5 board

    void play(int number) {
        for (int &i: numbers) {
            if (i == number) {
                i = -1;
                break;
            }
        }
    }

    bool is_bingo() {
        // check rows
        for (int i = 0; i < 5; i++) {
            bool bingo = true;
            for (int j = 0; j < 5; j++) {
                if (numbers[i * 5 + j] != -1) {
                    bingo = false;
                    break;
                }
            }
            if (bingo) {
                return true;
            }
        }

        // check columns
        for (int i = 0; i < 5; i++) {
            bool bingo = true;
            for (int j = 0; j < 5; j++) {
                if (numbers[i + j * 5] != -1) {
                    bingo = false;
                    break;
                }
            }
            if (bingo) {
                return true;
            }
        }

        return false;
    }
};

vector<Board> parse_boards(const vector<string> &data);

int sum_board(int number, Board &board);

struct S1 : public StarBase {
    S1() : StarBase(4, 1) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        vector<int> numbers = aoc::split_to_ints(data[0], ",");
        vector<Board> boards = parse_boards(data);

        for (int number: numbers) {
            for (Board &board: boards) {
                board.play(number);
                if (board.is_bingo()) {
                    return sum_board(number, board);
                }
            }
        }

        return -1;
    }

};

struct S2 : public StarBase {
    S2() : StarBase(4, 2) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        vector<int> numbers = aoc::split_to_ints(data[0], ",");
        vector<Board> boards = parse_boards(data);

        for (int number: numbers) {
            auto it = boards.begin();
            while (it != boards.end()) {
                Board &board = *it;
                board.play(number);
                if (board.is_bingo()) {
                    if (boards.size() == 1) {
                        return sum_board(number, board);
                    }
                    boards.erase(it);
                } else {
                    it++;
                }
            }
        }

        return -1;
    }
};


vector<Board> parse_boards(const vector<string> &data) {
    vector<Board> boards;
    Board board;
    for (int i = 2; i < data.size(); i++) {
        const string &line = data[i];
        int row_number = (i - 2) % 6;
        if (row_number == 5) { // new bingo board
            boards.push_back(board);
            board = Board();
            continue;
        } else {
            vector<int> row_numbers = aoc::split_to_ints(line, " ");
            for (int j = 0; j < row_numbers.size(); j++) {
                board.numbers[row_number * 5 + j] = row_numbers[j];
            }
        }
    }
    boards.push_back(board);
    return boards;
}

int sum_board(int number, Board &board) {
    int sum = 0;
    for (int i: board.numbers) {
        if (i != -1) {
            sum += i;
        }
    }
    return number * sum;
}


int main() {
    S1 s1;
    s1.run_test(4512);
    s1.run(60368);

    S2 s2;
    s2.run_test(1924);
    s2.run(17435);

    return 0;
}