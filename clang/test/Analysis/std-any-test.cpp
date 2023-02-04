// RUN: %clang %s -Xclang -verify --analyze \
// RUN:   -Xclang -analyzer-checker=core \
// RUN:   -Xclang -analyzer-checker=debug.ExprInspection \
// RUN:   -Xclang -analyzer-checker=alpha.core.StdVariant

#include <any>
#include <string>
#define MAGIC_NUMBER 21

class DummyClass {
  public:
  void f() {};
};

struct LargeClass {
    public:
    long long elem, a, b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,asasasasa, aa, ab, aaa, ls, qwert, trewq, asd, ds;
    char bigStringOne[10000] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    char bigStringTwo[10000] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
};


struct A {
  int i;
};

struct B {
  int i;
};

void clang_analyzer_eval(int);
void clang_analyzer_warnIfReached();
template <typename T>
constexpr void clang_analyzer_dump(T) {}

template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

void reasonAboutValueHeldInAny() {
  std::any a = MAGIC_NUMBER;
  int valueFromAny = std::any_cast<int> (a);
  clang_analyzer_eval(valueFromAny == MAGIC_NUMBER); // expected-warning{{TRUE}}
}
void reasonAboutBigValueHeldInAny() {
  LargeClass lc{MAGIC_NUMBER};
  std::any a = lc;
  LargeClass valueFromAny = std::any_cast<LargeClass> (a);
  clang_analyzer_eval(valueFromAny.elem == MAGIC_NUMBER); // expected-warning{{TRUE}}
}

// check weather the analyzer can reason about primitive types in std::any
void reasoningAboutTypeHeldInAny() {
  std::any a = MAGIC_NUMBER;
  std::any b = 22;

  int i = std::any_cast<int> (a);
  clang_analyzer_warnIfReached(); // expected-warning{{REACHABLE}}
  // if we reach this point that means the analyzer knows that the std::any holds an int

  int j = std::any_cast<int> (b);
  clang_analyzer_warnIfReached(); // expected-warning{{REACHABLE}}
  
  std::any a1 = A{5};
  B baaa = std::any_cast<B> (a1);
  
  clang_analyzer_warnIfReached(); // no-warning

  DummyClass d = std::any_cast<DummyClass> (a);
  clang_analyzer_warnIfReached(); // no-warning
  // if we won't reach this point that means the analyzer
  // has stopped the construction of Exploided Graph in this path
  // becasue it knows that any_cast function call will fail
  d.f();
  i++;
  j++;
  baaa.i++;
}

// check weather the analyzer can reason about large types in std::any
void reasonAboutBigTypeHeldInAny() {
  LargeClass lc{MAGIC_NUMBER};
  std::any a = lc;

  LargeClass lv2 = std::any_cast<LargeClass> (a);
  clang_analyzer_warnIfReached(); // expected-warning{{REACHABLE}}
  // if we reach this point that means the analyzer knows that the std::any
  // holds a LargeClass user defined type

  int d = std::any_cast<int> (a);
  clang_analyzer_warnIfReached(); // no-warning
  d++;
  lv2.elem++;
}

void reasonAboutAnyPointer() {
  std::any a = MAGIC_NUMBER;
  int* i = std::any_cast<int> (&a);
  clang_analyzer_warnIfReached(); // expected-warning{{REACHABLE}}
  clang_analyzer_eval(*i == MAGIC_NUMBER); // expected-warning{{TRUE}}
  a = 3.14;
  float* f = std::any_cast<float> (&a);
  i = std::any_cast<int> (&a);
  clang_analyzer_warnIfReached(); // no-warning
  (*i)++;
  (*f)++;
}
