#include <iostream>
#include <map>
#include <functional>
#include <ranges>



using namespace std;

struct cache_item {
    string key;
    string value;
    size_t counter{0};

    void print() const {
        cout << key << " -> " << value << ", counter: " << counter << endl;
    }

    // Doesn't work. Because priority_queue stores pointers?
    // bool operator<(const cache_item *item) const {
    //     return counter < item->counter;
    // }
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
        item->print();
    }

private:
    cache_item *const item; // TODO Too many consts?
};

struct cache {
    explicit cache(const size_t size) : size(size) {
        // TODO std::atomic, + make sure you dont delete records under hands
    }

    ~cache() {
        for (auto &[_, item]: items) {
            delete item;
        }
    }

    cache_item_ptr get_item(const string &key) {
        if (!items.contains(key)) {
            auto *new_item = new cache_item{key, to_string(key.size())}; // TODO Custom memory management


            if (items.size() >= size) {

                // TODO How does this work? Cannot get anything from lfu_item
                // auto cache_values = views::values(items);
                // auto lfu_item = min_element(cache_values.begin(), cache_values.end(),
                //       [](const cache_item *l, const cache_item *r) { return l->counter < r->counter; });

                auto * lfu_item = min_element(items.begin(), items.end(),
                    [](const auto& l, const auto& r) { return l.second->counter < r.second->counter; })->second;

                cout << "Evicting " << lfu_item->key << " (counter: " << lfu_item->counter << ")" << endl;

                items.erase(lfu_item->key);
                delete lfu_item;

            }

            items[key] = new_item;
        }
        return cache_item_ptr{items[key]};
    }

private:
    size_t size;
    map<string, cache_item *> items;

};


int main() {
    cache c(2);

    const auto ptr1 = c.get_item("foo1");
    ptr1->value;
    ptr1->value;

    const auto ptr2 = c.get_item("foo2");
    ptr2->value;

    // evict foo2
    const auto ptr3 = c.get_item("foo3");
    ptr3->value;
    ptr3->value;
    ptr3->value;

    // evict foo1
    c.get_item("foo4");

    return 0;
}
