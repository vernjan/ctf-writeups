#include <iostream>
using namespace std;

namespace jve {

    struct vector {
        int elms[10];
        size_t index = 0;
    
        size_t size() const {
            return index;
        }
    
        void push_back(int const & value) {
            elms[index++] = value; // TODO call the move variant?
        }
    
        void push_back(int && value) {
            elms[index++] = value;
        }
    
        int at(size_t const & pos) const { // TODO return int&, size_t const & index ?
            if (pos >= this->index) {
                throw out_of_range("index is out of range"); // TODO string interpolation?
            }
            return elms[pos];
        }
    
        int get(size_t pos) {
            return elms[pos];
        }
    };
}

int main() 
{
    cout << "Hello, World!\n";
    jve::vector v;
    cout << "Size: " << v.size() << "\n";
    //std::puts("Size: " + v.size()); //???
    v.push_back(1);
    cout << "Size: " << v.size() << "\n";
    //std::puts("Size: " + v.size()); //???
    v.push_back(std::move(2));
    cout << "Index 0: " << v.get(0) << "\n";
    cout << "Index 1: " << v.get(1) << "\n";
    //cout << "Index 2: " << v.at(2) << "\n";
    return 0;
}