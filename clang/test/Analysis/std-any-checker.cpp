// RUN: %clang %s -Xclang -verify --analyze \
// RUN:   -Xclang -analyzer-checker=core \
// RUN:   -Xclang -analyzer-checker=debug.ExprInspection \
// RUN:   -Xclang -analyzer-checker=core,alpha.core.StdAny

#include <any>

void noTypeHeld() {
  std::any a;
  int i = std::any_cast<int>(a); // expected-warning {{any 'a' held a null type}}
  (void*)i;
}

void formVariabnle() {
  //auto i = 5;
  std::any a = 5;
  int b = std::any_cast<int>(a);
  char c = std::any_cast<char>(a); // expected-warning {{std::any 'a' held a(n) int not a(n) char}}
  (void*)b;
  (void*)c;
}

void pointerHeld() {
  std::any a = new int;
  int* x = std::any_cast<int*>(a);
  char c = std::any_cast<char>(a); // expected-warning {{std::any 'a' held a(n) int * not a(n) char}}
  (void**)x;
  (void*)c;
}

void reset() {
  std::any a = 15;
  a.reset();
  int i = std::any_cast<int>(a); // expected-warning {{any 'a' held a null type}}
  (void*)i;
}