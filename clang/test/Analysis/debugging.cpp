// RUN: %clang %s -std=c++17 -Xclang -verify --analyze

// struct A {
//     public:
//     A(int, int){}
// };

// struct C {
//     C(int){}
// };

// struct B : public A, public C {
//     B() : A(5, 6), C(12) {}
//     int a;    
// };

// int main() {
//     B baaaa{};
// }

// RUN: %clang %s -std=c++17 -Xclang -verify --analyze

// struct A {
//     public:
//     A(int, int){}
// };

// struct C {
//     C(int){}
// };

// struct B : public A, public C {
//     int a;    
// };

// int main() {
//     B b{A{1, 2}, C{12}, 3};
// }

class MyBase {
    private:
    int a, b;
    public:
    MyBase(int a, int b) : a(a), b(b) {}
    MyBase() = default;
};

class SecondBase {
    int a, b;
    public:
    SecondBase(int a, int b) : a(a), b(b) {}
};

class Derived : public MyBase, public SecondBase {
    public:
    int c;
    Derived(int a, int b, int c, int d, int e): MyBase(a, b), SecondBase(c, d), c(e) {}
};

int main() {
    // MostDerivedDefault dInstance(5,4,3);
    Derived d(1, 2, 3, 4, 5);
    return 0;
}