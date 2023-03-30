// RUN: %clang %s -Xclang -verify --analyze \
// RUN:   -Xclang -analyzer-checker=core \
// RUN:   -Xclang -analyzer-checker=debug.ExprInspection \
// RUN:   -Xclang -analyzer-checker=core,alpha.core.StdVariant

#include <variant>

//helper functions
void changeVraiantType(std::variant<int, char> &v) {
  v = 25;
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
  char c = std::get<1>(v);
  (void*)a;
  (void*)c;

}
//Verify that we warn when 
void stdGetType() {
  std::variant<int, char> v = 25;
  int a = std::get<int>(v);
  char c = std::get<char>(v);
  (void*)a;
  (void*)c;
}

void copyConstructor() {
  std::variant<int, char> v = 25;
  std::variant<int, char> t(v);
  int a = std::get<int> (t);
  char c = std::get<char> (t);
  (void*)a;
  (void*)c;

}

void copyAssignemntOperator() {
  std::variant<int, char> v = 25;
  std::variant<int, char> t = 'c';
  t = v;
  int a = std::get<int> (t);
  char c = std::get<char> (t);
  (void*)a;
  (void*)c;
}

void assignemntOperator() {
  std::variant<int, char> v = 25;
  int a = std::get<int> (v);
  (void*)a;
  v = 'c';
  char c = std::get<char>(v);
  a = std::get<int>(v);
  (void*)a;
  (void*)c;
}

void defaultConstructor() {
  std::variant<int, char> v;
  int i = std::get<int>(v);
  char c = std::get<char>(v);
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

void functionCall() {
  //here is the problem
  std::variant<int, char> v = 'c';
  changesToInt(v);
  int a = std::get<int> (v);
  char c = std::get<char> (v);
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