#include <iostream>
#include <limits>

using std::cout;

// https://en.cppreference.com/w/cpp/container/vector
// https://gcc.gnu.org/onlinedocs/gcc-4.6.2/libstdc++/api/a01069_source.html

void print_array(const int *p, size_t size);

namespace jve {

    constexpr int DEFAULT_VECTOR_SIZE = 16;

    template<typename T>
    class vector {
    public:

        vector() : vector(DEFAULT_VECTOR_SIZE) {
            cout << "vector()\n";
        }

        // TODO What are the default values? new T[count] vs. new T[count]() vs. new T[count]{}
        explicit vector(size_t count) : elms(new T[count]) {
            cout << "vector(size_t)\n";
        }

        // TBD - push_back and emplace_back, insert, erase, resize

        T &at(size_t pos) {
            if (pos > this->index) {
                throw std::out_of_range("index is out of range"); // TODO string interpolation?
            }
            return elms[pos];
        }

        [[nodiscard]] const T &
        at(size_t pos) const { // TODO Why STL usually has const/const overload for methods? How do I call this overload?
            if (pos > this->index) {
                throw std::out_of_range("index is out of range");
            }
            return elms[pos];
        }

        T &operator[](size_t pos) {
            return elms[pos];
        }

        T &front() {
            return elms[0];
        }

        T &back() {
            return elms[index];
        }

        T *data() {
            return &elms[0];
        }

        [[nodiscard]] size_t size() const {
            return index + 1;
        }

        void push_back(T const &value) {
            elms[++index] = value;
//            push_back(std::move(value)); // TODO Why is this a recursive call?
        }

        void push_back(T &&value) {
            elms[++index] = value;
        }

        T get(size_t pos) {
            return elms[pos];
        }

    private:
        T *elms{nullptr};
        size_t index = std::numeric_limits<size_t>::max();

    };
}// namespace jve

void print_array(const int *p, size_t size) {
    cout << "data = ";
    for (size_t i = 0; i < size; i++) {
        cout << i << ":" << p[i] << ", ";
    }
    cout << '\n';
}


int main() {
    cout << "Vector v1:\n";
    jve::vector<int> v1; // default constructor
    int x = 2;
    int y = 4;
    v1.push_back(1); // calls && (rvalue)
    v1.push_back(x); // calls & (lvalue)
    v1.push_back(x + 1); // calls && (rvalue)
    v1.push_back(std::move(y)); // calls && (rvalue)
    cout << "size = " << v1.size() << "\n";
    print_array(v1.data(), v1.size());
    cout << "front = " << v1.front() << "\n";
    cout << "back = " << v1.back() << "\n";
    cout << "index 1 = " << v1.get(1) << "\n";
    cout << "index 1 = " << v1.at(1) << "\n";
    cout << "index 1 = " << v1[1] << "\n";
    // modify the reference
    int const &z = v1.at(1);  // TODO Why not calling the const overload?
    cout << z << "\n";
    v1.at(1) = 12; // returns a reference so we can re-assign
    v1[2] = 13;
    int &temp = v1[3]; // returns a reference
    temp = 14; // re-assign
    print_array(v1.data(), v1.size());

    cout << "\nVector v2:\n";
    jve::vector<int> v2(5);
    print_array(v2.data(), 5);

    return 0;
}