
class B {
    int a;
    public:
    B(int a): a(a){}
};

class D : public B {
    int b;
    public:
    D(int a, int b) : B(a), b(b){}
};

int main() {
    D d(5, 8);
}