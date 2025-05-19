#include <algorithm>
#include <iostream>
#include <map>
#include <functional>
#include <atomic>
#include <ranges>


// using namespace std;

struct cache_item {
    std::string key;
    std::string value;
    size_t usage_counter{0};
    std::atomic<int> ptr_counter{0};


    void print() const {
        std::cout << key << " -> " << value << ", counter: " << usage_counter << std::endl;
    }
};

struct cache_item_ptr {
    explicit cache_item_ptr(cache_item *const item) : item(item) {
        ++item->ptr_counter;
    }

    const cache_item *operator->() const {
        // cout << "operator -> ";
        ++item->usage_counter;

        return item;
    }

    void print() const {
        item->print();
    }

    ~cache_item_ptr() {
        std::cout << "Deleting " << item->key << std::endl;
        --item->ptr_counter;
    }

private:
    cache_item *const item;
};

struct cache {
    explicit cache(const size_t size) : size(size) {

    }

    ~cache() {
        for (auto &[_, item]: items) {
            delete item;
        }
    }

    cache_item_ptr get_item(const std::string &key) {
        if (!items.contains(key)) {
            auto *new_item = new cache_item{key, std::to_string(key.size())}; // TODO Custom memory management

            if (items.size() >= size) {
                // 1) filter items - keep items with ptr_counter == 0
                // 2) sort by usage_counter ascendingly
                // 3) remove first n items where n = items.size - size

                // TODO Pre-fetch usage counters to make sorting more effective,
                // or avoid sorting and prefer array iterations
                auto unused_cache_items = items
                                               | std::views::values
                                               | std::views::filter([](const cache_item *item) {
                                                   return item->ptr_counter == 0;
                                               });

                std::vector<cache_item *> evictable_items;
                std::ranges::copy(unused_cache_items, std::back_inserter(evictable_items));

                std::ranges::sort(evictable_items,
                                  [](auto *a, auto *b) { return a->usage_counter < b->usage_counter; });

                const size_t number_of_items_to_remove = (items.size() - size) + 1;
                for (size_t i = 0; i < number_of_items_to_remove && i < evictable_items.size(); ++i) {
                    const auto *item_to_remove = evictable_items[i];
                    std::cout << "Evicting " << item_to_remove->key
                            << " (counter: " << item_to_remove->usage_counter << ")" << std::endl;
                    items.erase(item_to_remove->key);
                    delete item_to_remove;
                }
            }

            items[key] = new_item;
        }
        return cache_item_ptr{items[key]};
    }

private:
    size_t size;
    std::map<std::string, cache_item *> items;
};


int main() {
    cache c(2);

    {
        {
            const auto ptr1 = c.get_item("ptr1");
            ptr1->value;
            ptr1->value;
        } // delete ptr1

        const auto ptr2 = c.get_item("ptr2");
        ptr2->value;

        std::cout << "HERE1" << std::endl;

        // evict ptr1 because ptr2 (with fewer usages) is still being used
        const auto ptr3 = c.get_item("ptr3");
        ptr3->value;
        ptr3->value;
        ptr3->value;

        std::cout << "HERE2" << std::endl;
    } // delete ptr3, ptr2

    std::cout << "HERE3" << std::endl;

    // evict ptr2 with fewer usages
    c.get_item("ptr4");

    // ptr1->value; // boom - cached item was evicted

    return 0;
}
