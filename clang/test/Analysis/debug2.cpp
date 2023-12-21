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
    int a;
    public:
    MyBase(int a) : a(a) {}
};

class Derived : public MyBase {
    public:
    int c;
};



int main() {
    // MostDerivedDefault dInstance(5,4,3);
    Derived d{1, 2};
    return 0;
}