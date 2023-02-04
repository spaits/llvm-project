// RUN: %clang %s -Xclang -verify --analyze \
// RUN:   -Xclang -analyzer-checker=core \
// RUN:   -Xclang -analyzer-checker=debug.ExprInspection

#include <any>

struct DummyClass {
    int i;
    char c;
};

struct LargeClass {
    long long a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p;
    char s1[1024];
    char s2[1024];
    char cc;
};

void clang_analyzer_eval(int);
template <typename T>
constexpr void clang_analyzer_dump(T) {}
void clang_analyzer_warnIfReached();

void reasonAboutVariableHeldinAny() {
    std::any a = 15;
    std::any b = 25;

    int integerFromAnyA = std::any_cast<int>(a);
    clang_analyzer_eval(15 == integerFromAnyA); // expected-warning{{TRUE}}
    int integerFromAnyB = std::any_cast<int>(b);
    clang_analyzer_eval(25 == integerFromAnyB); // expected-warning{{TRUE}}

    a = 'c';
    char charFromAny = std::any_cast<char>(a);
    clang_analyzer_eval('c' == charFromAny); // expected-warning {{TRUE}}

    int somethingElse = std::any_cast<int>(a);
    clang_analyzer_warnIfReached();
    somethingElse++;
}

void checkWarnIf() {
    std::any a = DummyClass{15, 'c'};
    DummyClass dummyClassFromAny = std::any_cast<DummyClass>(a);
    int integerFromDummyClass = dummyClassFromAny.i;
    char charFromDummyClass = dummyClassFromAny.c;
    clang_analyzer_eval(15 == integerFromDummyClass); // expected-warning {{TRUE}}
    clang_analyzer_eval('c' == charFromDummyClass); // expected-warning {{TRUE}}

    LargeClass lc;
    a = lc;
    lc.a = 15;
    lc.cc = 'c';
    LargeClass largeClassFromAny = std::any_cast<LargeClass>(a);
    int aFromLargeClass = largeClassFromAny.a;
    char ccFromLargeClass = largeClassFromAny.cc;

    clang_analyzer_dump(aFromLargeClass);
    clang_analyzer_dump(ccFromLargeClass);
    clang_analyzer_eval(15 == aFromLargeClass); // expected-warning {{TRUE}}
    clang_analyzer_eval('c' == ccFromLargeClass); // expected-warning {{TRUE}}
    
}