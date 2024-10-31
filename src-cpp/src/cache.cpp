#include <string>
#include <map>
#include <stdexcept>
#include <iostream>
#include <cassert>

const int SALT_SIZE = 4;
const int DATA_SIZE = 8;

struct salt {
    char salt_[SALT_SIZE];

    std::string to_string() {
        std::string result;
        for (int i = 0; i < SALT_SIZE; ++i) {
            result += salt_[i];
        }
        return result;
    }

    bool operator==(const salt &rhs) const {
        return std::equal(salt_, salt_ + SALT_SIZE, rhs.salt_);
    }

    bool operator!=(const salt &rhs) const {
        return !operator==(rhs); // TODO ???
    }
};

static salt rand_salt() {
    salt result{};
    for (char &ch: result.salt_) {
        ch = static_cast<char>('a' + rand() % 26);
    }
    return result;
}

static std::array<char, DATA_SIZE> rand_data() {
    std::array<char, DATA_SIZE> result{};
    for (char &ch: result) {
        ch = static_cast<char>('A' + rand() % 26);
    }
    return result;
}

struct read_result {

    read_result(const salt &salt, const std::array<char, DATA_SIZE> &data) : salt_(salt), data(data) {
        print();
    }

    void print() {
        std::cout << "  --> Salt: ";
        for (char i: salt_.salt_) {
            std::cout << i;
        }
        std::cout << ", Data: ";
        for (char i: data) {
            std::cout << i;
        }
        std::cout << std::endl;
    }

    salt salt_{};
    std::array<char, DATA_SIZE> data{};
};

struct cache_item {

    void print() {
        std::cout << "Salt: ";
        for (char i: salt_.salt_) {
            std::cout << i;
        }
        std::cout << ", Data: ";
        for (char i: data) {
            std::cout << i;
        }
        std::cout << ", Source index: " << source_index;
        std::cout << std::endl;
    }

    cache_item() {
        std::cout << "  --> Creating new cache item" << std::endl;
    }

    salt salt_{};
    std::array<char, DATA_SIZE> data{};
    size_t source_index{};
    bool valid{true};
//    size_t hits{0}; // TODO implement least frequently used
};


struct source_reader {

    explicit source_reader(ushort cache_size) :
            cache_size{cache_size},
            // https://www.geeksforgeeks.org/placement-new-operator-cpp/
            cache_items{reinterpret_cast<cache_item *>(new char[sizeof(cache_item) * cache_size])} {}

    ~source_reader() {
        delete[] cache_items;
    }

    read_result read(size_t source_index) {
        std::cout << "Reading index: " << source_index << std::endl;
        std::cout << "  --> Loading data into cache (cache_index: " << cache_index << ") ......" << std::endl;

        cache_item &old_cache_item = cache_items[cache_index];
        if (old_cache_item.valid) { // TODO How else do I know it's valid cache item? Could be all 0s ..
            std::cout << "  --> Removing old cache item: " << old_cache_item.source_index << ":" << cache_index << std::endl;
            old_cache_item.~cache_item(); // placement delete
            cache_mapping.erase(old_cache_item.source_index);
        }

        auto *item = new(cache_items + cache_index) cache_item{}; // placement new
        item->salt_ = rand_salt();
        if (source_data.find(source_index) == source_data.end()) { // just to always return the same source data
            source_data[source_index] = rand_data();
        }
        item->data = source_data[source_index];
        item->source_index = source_index;

        cache_mapping[source_index] = cache_index;
        cache_index = (cache_index + 1) % cache_size; // TODO use least frequently used

        return read_result{item->salt_, item->data};
    }

    read_result read(size_t index, salt salt) {
        std::cout << "Reading index: " << index << " and salt: " << salt.to_string() << std::endl;

        if (cache_mapping.find(index) != cache_mapping.end()) {
            cache_item &item = cache_items[cache_mapping[index]];
            if (item.salt_ == salt) {
                return read_result{item.salt_, item.data};
            }
        }
        std::cout << "  --> Cache item was invalidated, re-reading from source ......" << std::endl;
        return read(index); // cache was invalidated
    }

private:
    ushort cache_size;
    cache_item *cache_items{};
    std::map<size_t, ushort> cache_mapping{};
    ushort cache_index{0};

    std::map<size_t, std::array<char, DATA_SIZE>> source_data;
};


int main() {
    source_reader reader{3};

    read_result result0a = reader.read(0);
    read_result result0b = reader.read(0, result0a.salt_); // cache is already loaded
    assert(result0a.data == result0b.data && result0a.salt_ == result0b.salt_);
    std::cout << std::endl;

    read_result result1 = reader.read(1);
    read_result result2 = reader.read(2); // cache is full now
    std::cout << std::endl;

    read_result result3 = reader.read(3); // cache_index 0 points to index 3 now
    std::cout << std::endl;

    read_result result0c = reader.read(0, result0a.salt_); // cache_index 1 points to index 0
    assert(result0a.data == result0c.data && result0a.salt_ != result0c.salt_);
    std::cout << std::endl;

    std::cout << "PASSED" << std::endl;

    return 0;
}