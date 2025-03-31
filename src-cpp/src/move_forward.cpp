#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <utility>
#include <ranges>


struct A {
    int foo = 65;

    A(int foo) : foo(foo) {
        std::cout << "default constructor\n";
    }

    // copy constructor
    A(const A &a) {
        std::cout << "copy constructor\n";
    }

    // move constructor
    // A(A &&a) noexcept {
    //     std::cout << "move constructor\n";
    // }

    A(A &&a) = delete;

    // copy assignment
    A &operator=(const A &a) {
        std::cout << "copy assignment\n";
        return *this;
    }

    // // move assignment
    // A &operator=(A &&a) noexcept {
    //     std::cout << "move assignment\n";
    //     return *this;
    // }

    A &operator=(A &&a) = delete;



};

// void pass_a(A a) {
//     std::cout << "pass_a: foo=" << a.foo << "\n";
// }

// void pass_a(A & a) {
//     std::cout << "pass_a&: foo=" << a.foo << "\n";
// }

void pass_a(A && a) {
    std::cout << "pass_a&&: foo=" << a.foo << "\n";
    // auto l = [a = std::move(a)]() {
    //     std::cout << "lambda\n";
    // };
    // l();
}

// A get_a(int x) {
//     std::cout << "get_a: x=" << x << "\n";
//     if (x < 50) {
//         A a1 = A{77};
//         return a1;
//     }
//     A a2 = A{88};
//     return a2;
// }

int main() {
    A a1 = {556};
    // A & a2 = a1;

    pass_a(std::move(a1));
    // pass_a(A{88});
    // srand(time(0));
    // A a2 = get_a(rand() % 100);
    // pass_a(std::move(a2));
}



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
//        Miau::YYY(std::forward<T>(t));
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

// int main() {
//     // B: &Bar
//     Bar b1{};
//     Foo<Bar>::XXX(b1);
//     std::cout << "\n";
//     // C: const &Bar
//     const Bar b2{};
//     Foo<Bar>::XXX(b2);
//     std::cout << "\n";
//     // D: &&Bar
//     Foo<Bar>::XXX(Bar{});
//     std::cout << "\n";
//     // E: const &&Bar
//     Foo<Bar>::XXX(std::move(b2));
//     std::cout << "\n";
//
//     Foo<Bar>::ZZZ(b1);
//     std::cout << "\n";
//     Foo<Bar>::ZZZ(Bar{});
//     std::cout << "\n";
// }