// RUN: %clang %s -Xclang -verify --analyze \
// RUN:   -Xclang -analyzer-checker=core \
// RUN:   -Xclang -analyzer-checker=debug.ExprInspection \
// RUN:   -Xclang -analyzer-checker=core,alpha.core.StdVariant

#include <variant>

//helper functions
void changeVraiantType(std::variant<int, char> &v) {
  v = 25;
}

void swap(std::variant<int, char> &v1, std::variant<int, char> &v2) {
  std::variant<int, char> tmp = v1;
  v1 = v2;
  v2 = tmp;
}

void cantDo(const std::variant<int, char>& v) {
  std::variant<int, char> vtmp = v;
  vtmp = 5;
  int a = std::get<int> (vtmp);
  (void*) a;
}

using var_t = std::variant<int, char>;
using var_tt = var_t;
using int_t = int;
using char_t = char;

void changesToInt(std::variant<int, char> &v);

//Verify that we warn when we try to get the wrong type out of variant and
//We do not warn when we try to get the stored type 
void stdGetIntegral() {
  std::variant<int, char> v = 25;
  // variant t is here to see wether we can distinguish between two variants
  // variants are identifieb by their memmory region
  std::variant<int, char> t = 'c';
  int a = std::get<0>(v);
  char c = std::get<1>(v); // expected-warning {{variant 'v' held a(n) int not a(n) char}}
  (void*)a;
  (void*)c;

}
//Verify that we warn when 
void stdGetType() {
  std::variant<int, char> v = 25;
  int a = std::get<int>(v);
  char c = std::get<char>(v); // expected-warning {{variant 'v' held a(n) int not a(n) char}}
  (void*)a;
  (void*)c;
}

void copyConstructor() {
  std::variant<int, char> v = 25;
  std::variant<int, char> t(v);
  int a = std::get<int> (t);
  char c = std::get<char> (t); // expected-warning {{variant 't' held a(n) int not a(n) char}}
  (void*)a;
  (void*)c;

}

void copyAssignemntOperator() {
  std::variant<int, char> v = 25;
  std::variant<int, char> t = 'c';
  t = v;
  int a = std::get<int> (t);
  char c = std::get<char> (t); // expected-warning {{variant 't' held a(n) int not a(n) char}}
  (void*)a;
  (void*)c;
}

void assignemntOperator() {
  std::variant<int, char> v = 25;
  int a = std::get<int> (v);
  (void*)a;
  v = 'c';
  char c = std::get<char>(v);
  a = std::get<int>(v); // expected-warning {{variant 'v' held a(n) char not a(n) int}} 
  (void*)a;
  (void*)c;
}

void defaultConstructor() {
  std::variant<int, char> v;
  int i = std::get<int>(v);
  char c = std::get<char>(v); // expected-warning {{variant 'v' held a(n) int not a(n) char}}
  (void*)i;
  (void*)c;
}

//NOT GOOD
void inlineFunctionCall() {
  std::variant<int, char> v = 'c';
  changeVraiantType(v);
  int a = std::get<int> (v);
  char c = std::get<char> (v);
  (void*)a;
  (void*)c;
}

void functionCallwithAssignemnt() {
  //here is the problem
  std::variant<int, char> v = 'c';
  changesToInt(v);
  int a = std::get<int> (v);
  char c = std::get<char> (v); // expected-warning {{}}
  (void*)a;
  (void*)c;
}

void functionCallWithCopyAssignment() {
  var_t v1 = 15;
  var_t v2 = 'c';
  swap(v1, v2);
  int a = std::get<int> (v2);
  (void*)a;
  char c = std::get<char> (v1);
  a = std::get<int> (v1); // expected-warning {{}}
  (void*)a;
  (void*)c;

}

void typefdefedVariant() {
  var_t v = 25;
  int a = std::get<int>(v);
  char c = std::get<char>(v);
  (void*)a;
  (void*)c;
}

void typedefedTypedfefedVariant() {
  var_tt v = 25;
  int a = std::get<int>(v);
  char c = std::get<char>(v);
  (void*)a;
  (void*)c;
}

void typdefedGet() {
  std::variant<char, int> v = 25;
  int a = std::get<int_t>(v);
  char c = std::get<char_t>(v);
  (void*)a;
  (void*)c;
}

void typedefedPack() {
  std::variant<int_t, char_t> v = 25;
  int a = std::get<int>(v);
  char c = std::get<char>(v);
  (void*)a;
  (void*)c;
}

//What we do not report on, but we should
void valueHeld() {
  std::variant<int, char> v = 0;
  int a = std::get<int>(v);
  int div = 10/a; // we should report a divison by 0 here
  (void*)div;
  (void*)a;
}

void stdGetIf() {
  std::variant<int, char> v = 'c';
  int* i = std::get_if<int>(&v);
  (*i)++; //we should report a dereference of a null pointer here
  (void**)i;
}

//move constructor
//move assignment