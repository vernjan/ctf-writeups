#include <iostream>
using namespace std;

// https://en.cppreference.com/w/cpp/container/vector
// https://gcc.gnu.org/onlinedocs/gcc-4.6.2/libstdc++/api/a01069_source.html

void pointer_func(const int *p, std::size_t size) {
    std::cout << "data = ";
    for (std::size_t i = 0; i < size; i++) {
        std::cout << p[i] << ' ';
    }
    std::cout << '\n';
}

namespace jve {

    template<typename T>
    struct vector {
        // typedef size_t size_type;

        T elms[10]{};
        size_t index = 0;// TODO -1

        // TODO here - constructors
        vector() = default;
        explicit vector(size_t count) {}

        T &at(size_t pos) {
            if (pos >= this->index) {
                throw out_of_range("index is out of range");// TODO string interpolation?
            }
            return elms[pos];
        }

        [[nodiscard]] const T &at(size_t pos) const {// TODO why always having const/const overload?
            if (pos >= this->index) {
                throw out_of_range("index is out of range");
            }
            return elms[pos];
        }

        T &operator[](size_t pos) {
            return elms[pos];
        }

        T &front() {
            return elms[0];
        }

        // TODO back()

        T *data() {
            return &elms[0];
        }

        [[nodiscard]] size_t size() const {
            return index;
        }

        void push_back(T const &value) {
            elms[index++] = value;// TODO call the move variant?
        }

        void push_back(T &&value) {
            elms[index++] = value;
        }


        T get(size_t pos) {
            return elms[pos];
        }
    };
}// namespace jve

int main() {
    cout << "Hello, World!\n";
    jve::vector<int> v;
    //jve::vector<int> v2{1,2,3};  // TODO not supported yet
    //cout << "Size: " << v2.size() << "\n";
    cout << "Size: " << v.size() << "\n";
    //std::puts("Size: " + v.size()); //???
    v.push_back(1);
    cout << "Size: " << v.size() << "\n";
    //std::puts("Size: " + v.size()); //???
    v.push_back(std::move(2));
    cout << "Index 0: " << v.front() << "\n";
    cout << "Index 1: " << v.get(1) << "\n";
    v.at(1) = 5;
    int &index1 = v.at(1);
    index1 = 7;
    cout << "Index 1: " << v[1] << "\n";
    pointer_func(v.data(), v.size());
    //cout << "Index 2: " << v.at(2) << "\n";
    return 0;
}