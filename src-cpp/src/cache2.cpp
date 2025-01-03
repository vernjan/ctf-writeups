#include <iostream>
#include <map>

using namespace std;

struct cache_item {
    string key;
    string value;
    size_t counter{0};
};

struct cache_item_ptr {
    explicit cache_item_ptr(cache_item *const item) : item(item) {
    }

    const cache_item *operator->() const {
        // cout << "operator -> ";
        item->counter++;
        return item;
    }

    void print() const {
        cout << item->key << " -> " << item->value << ", counter: " << item->counter << endl;
    }

private:
    cache_item *const item; // TODO Too many consts?
};

struct cache {
    explicit cache(const size_t size) : size(size) {
        // TODO Size limit + eviction strategies
    }

    ~cache() {
        for (auto &[_, item]: items) {
            delete item;
        }
    }

    cache_item_ptr get_item(const string &key) {
        if (!items.contains(key)) {
            items[key] = new cache_item{key, to_string(key.size())}; // TODO Custom memory management
        }
        return cache_item_ptr{items[key]};
    }

private:
    size_t size;
    map<string, cache_item *> items;
};


int main() {
    cache c(16);

    const auto ptr1a = c.get_item("foo");
    ptr1a.print();
    ptr1a->value;
    ptr1a.print();

    const auto ptr1b = c.get_item("foo");
    ptr1b.print();
    ptr1b->value;
    ptr1b.print();

    return 0;
}
