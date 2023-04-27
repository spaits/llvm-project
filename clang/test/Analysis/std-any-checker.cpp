// RUN: %clang %s -Xclang -verify --analyze \
// RUN:   -Xclang -analyzer-checker=core \
// RUN:   -Xclang -analyzer-checker=debug.ExprInspection \
// RUN:   -Xclang -analyzer-checker=core,core.StdAny

#include <any>

void clang_analyzer_warnIfReached();
void clang_analyzer_eval(int);


class DummyClass{
  public:
  void foo(){};
};

void nonInlined(std::any &a);
void nonInlinedConst(const std::any & a);

void inlined(std::any &a) {
  a = 5;
}

using any_t = std::any;
using any_tt = any_t;


//----------------------------------------------------------------------------//
// std::any_cast
//----------------------------------------------------------------------------//
void objectHeld() {
  std::any a = DummyClass{};
  DummyClass d = std::any_cast<DummyClass>(a);
  d.foo();
}

void formVariable() {
  //auto i = 5;
  std::any a = 5;
  int b = std::any_cast<int>(a);
  char c = std::any_cast<char>(a); // expected-warning {{std::any 'a' held a(n) int not a(n) char}}
  (void*)b;
  (void*)c;
}

void pointerHeld() {
  int i = 5;
  std::any a = &i;
  int* x = std::any_cast<int*>(a);
  char c = std::any_cast<char>(a); // expected-warning {{std::any 'a' held a(n) int * not a(n) char}}
  (void**)x;
  (void*)c;
}

//----------------------------------------------------------------------------//
// Null type
//----------------------------------------------------------------------------//

void noTypeHeld() {
  std::any a;
  int i = std::any_cast<int>(a); // expected-warning {{any 'a' held a null type}}
  (void*)i;
}
void reset() {
  std::any a = 15;
  a.reset();
  int i = std::any_cast<int>(a); // expected-warning {{any 'a' held a null type}}
  (void*)i;
}


//----------------------------------------------------------------------------//
// Typedefs
//----------------------------------------------------------------------------//

void typedefedAny () {
  any_t a = 5;
  int i = std::any_cast<int>(a);
  char c = std::any_cast<char>(a); // expected-warning {{std::any 'a' held a(n) int not a(n) char}}
  (void*)i;
  (void*)c;
}

void typedefedTypedefedAny () {
  any_tt a = 5;
  int i = std::any_cast<int>(a);
  char c = std::any_cast<char>(a); // expected-warning {{std::any 'a' held a(n) int not a(n) char}}
  (void*)i;
  (void*)c;
}

//----------------------------------------------------------------------------//
// Constructors and assignments
//----------------------------------------------------------------------------//

void assignemntOp () {
  std::any a;
  a = 5;
  int i = std::any_cast<int>(a);
  char c = std::any_cast<char>(a); // expected-warning {{std::any 'a' held a(n) int not a(n) char}}
  (void*)i;
  (void*)c;
}

void constructor() {
  std::any a(5);
  int i = std::any_cast<int>(a);
  char c = std::any_cast<char>(a); // expected-warning {{std::any 'a' held a(n) int not a(n) char}}
  (void*)i;
  (void*)c;
}

void copyCtor() {
  std::any a(5);
  std::any b(a);
  int i = std::any_cast<int>(a);
  char c = std::any_cast<char>(a); // expected-warning {{std::any 'a' held a(n) int not a(n) char}}
  (void*)i;
  (void*)c;
}

void copyCtorNullType() {
  std::any a;
  std::any b(a);
  char c = std::any_cast<char>(a); // expected-warning {{any 'a' held a null type}}
  (void*)c;
}

void copyAssignment() {
  std::any a = 5;
  std::any b = 'c';
  char c = std::any_cast<char>(b);
  (void*)c;
  b = a;
  int i = std::any_cast<int>(b);
  c = std::any_cast<char>(b); // expected-warning {{std::any 'b' held a(n) int not a(n) char}}
  (void*)i;
  (void*)c;
}

//----------------------------------------------------------------------------//
// Function calls
//----------------------------------------------------------------------------//

void nonInlinedRefCall() {
  std::any a = 5;
  nonInlined(a);
  int i = std::any_cast<int>(a);
  char c = std::any_cast<char>(a);
  (void*)i;
  (void*)c;
}

void nonInlinedConstRefCall() {
  std::any a = 5;
  nonInlinedConst(a);
  int i = std::any_cast<int>(a);
  char c = std::any_cast<char>(a); // expected-warning {{std::any 'a' held a(n) int not a(n) char}}
  (void*)i;
  (void*)c;
}

void inlinedCall() {
  std::any a = 'c';
  inlined(a);
  int i = std::any_cast<int>(a);
  char c = std::any_cast<char>(a); // expected-warning {{std::any 'a' held a(n) int not a(n) char}}
  (void*)i;
  (void*)c;
}

// imp dep

void valueHeld() {
  std::any a = 0;
  int i = std::any_cast<int>(a);
  clang_analyzer_eval(0 == i); // expected-warning{{TRUE}}
  int res = 5/i;
  clang_analyzer_warnIfReached(); // no-warning
  (void*)res;
}