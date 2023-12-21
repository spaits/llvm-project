// RUN: %clang %s -std=c++17 -Xclang -verify --analyze 
// class BaseForDefault {
//     int base;
//     public:
//     BaseForDefault(int b) : base(b) {}
// };

// class DerivedDefault : public BaseForDefault{
//     int derived;
//     public:
//     DerivedDefault(int fb, int d) : BaseForDefault(fb), derived(d) {}
// };

// class MostDerivedDefault : public DerivedDefault {
//     int mostDerived;
//     public:
//     MostDerivedDefault(int fb, int d, int md) : DerivedDefault(fb, d), mostDerived(md) {}
// };

// For test

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
};

class MostDerived : public Derived {
    public:
    int d;
};

int main() {
    // MostDerivedDefault dInstance(5,4,3);
    MostDerived d{{{1, 2}, {3,4}, 5},6};
    return 0;
}