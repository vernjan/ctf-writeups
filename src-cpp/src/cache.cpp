#include <string>
#include <map>
#include <stdexcept>
#include <iostream>

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
};

static salt rand_salt() {
    salt result{};
    for (char &ch: result.salt_) {
        ch = static_cast<char>('a' + (rand() % 26));
    }
//    result.salt_[SALT_SIZE - 1] = '\0';
    return result;
}

static std::array<char, DATA_SIZE> rand_data() {
    std::array<char, DATA_SIZE> result{};
    for (char &ch: result) {
        ch = static_cast<char>('A' + (rand() % 26));
    }
    return result;
}

struct read_result {

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
        std::cout << std::endl;
    }

    cache_item() {
//        std::cout << "  --> Creating cache item: ";
//        print();
    }

    salt salt_{};
    std::array<char, DATA_SIZE> data{};
//    size_t hits{0}; // TODO
};


struct source_reader {

    explicit source_reader(ushort cache_size) :
            cache_size{cache_size},
            // https://www.geeksforgeeks.org/placement-new-operator-cpp/
//            cache_items{new char [sizeof(cache_item) * cache_size]} {} // TODO: calls cache_item constructor, use Placement new operator in C++
            cache_items{new cache_item[cache_size]} {} // TODO: calls cache_item constructor, use Placement new operator in C++

    ~source_reader() {
        delete[] cache_items;
    }

    read_result read(size_t index) {
        std::cout << "Reading index: " << index << std::endl;

        std::cout << "  --> Loading data ......" << std::endl;
        auto item = cache_item{};
        item.salt_ = rand_salt();
        item.data = rand_data();

        cache_items[next_index] = item;
//        delete std::exchange(item, nullptr);
//        item = nullptr;
        cache_mapping[index] = next_index;

        next_index = (next_index + 1) % cache_size; // TODO use least frequently used

        return read_result{item.salt_, item.data};
    }

    read_result read(size_t index, salt salt) {
        std::cout << "Reading index: " << index << " and salt: " << salt.to_string() << std::endl;

        if (cache_mapping.find(index) == cache_mapping.end()) {
            throw std::runtime_error("Index not found in cache");
        }
        cache_item &item = cache_items[cache_mapping[index]];
        if (item.salt_ == salt) {
            return read_result{item.salt_, item.data};
        } else {
            // FIXME delete old cache item? Is it neccesary
            return read(index); // cache was invalidated
        }
    }

private:
    ushort cache_size;
    cache_item *cache_items{};
    std::map<size_t, ushort> cache_mapping{}; // FIXME not removing old items
    ushort next_index{0};
};


int main() {
    const int cache_size = 3;
    source_reader reader{cache_size};

    // fill cache
    read_result result1;
    for (size_t i = 0; i < cache_size; i++) {
        result1 = reader.read(i * DATA_SIZE);
        result1.print();
    }

    result1 = reader.read((cache_size - 1) * DATA_SIZE, result1.salt_);
    result1.print(); // same as before

    read_result result2 = reader.read(4 * DATA_SIZE); // invalidate first cache item
    result2.print();

    result1 = reader.read(4 * DATA_SIZE, result1.salt_);
    result1.print(); // same as before

    return 0;
}