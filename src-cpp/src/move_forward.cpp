#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <utility>


struct Bar {

    Bar() = default;

    // move constructor
    Bar(Bar &&b) noexcept: i(b.i), j(b.j), k(b.k) {
        std::cout << "move constructor\n";
    }

    int i{};
    int j{};
    int k{};
};

struct Miau {

    static void YYY(Bar &b) {
        std::cout << "1";
    }

    static void YYY(const Bar &b) {
        std::cout << "2";
    }

    static void YYY(Bar &&b) {
        std::cout << "3";
    }

    static void YYY(const Bar &&b) {
        std::cout << "4";
    }
};

template<typename T>
struct Foo {
    //static void XXX(T t) { std::cout << "A"; }
    static void XXX(T &t) {
        std::cout << "B";
        Miau::YYY(t);
        //        Miau::YYY(std::forward<T>(t));
        Miau::YYY(std::move(t));
    }

    static void XXX(const T &t) {
        std::cout << "C";
        Miau::YYY(t);
        Miau::YYY(std::forward<const T>(t));
        //        Miau::YYY(std::move(t));
    }

    static void XXX(T &&t) {
        std::cout << "D";
        Miau::YYY(t);
        Miau::YYY(std::forward<T>(t));
    }

    static void XXX(const T &&t) {
        std::cout << "E";
        Miau::YYY(t);
        Miau::YYY(std::forward<const T>(t));
    }

    template<typename Q>
    static void ZZZ(Q &&q) {
        std::cout << "X";
        Miau::YYY(q);
        Miau::YYY(std::forward<Q>(q));
    }
};

int main() {
    // B: &Bar
    Bar b1{};
    Foo<Bar>::XXX(b1);
    std::cout << "\n";
    // C: const &Bar
    const Bar b2{};
    Foo<Bar>::XXX(b2);
    std::cout << "\n";
    // D: &&Bar
    Foo<Bar>::XXX(Bar{});
    std::cout << "\n";
    // E: const &&Bar
    Foo<Bar>::XXX(std::move(b2));
    std::cout << "\n";

    Foo<Bar>::ZZZ(b1);
    std::cout << "\n";
    Foo<Bar>::ZZZ(Bar{});
    std::cout << "\n";
}