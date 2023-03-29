// RUN: %clang %s -Xclang -verify --analyze \
// RUN:   -Xclang -analyzer-checker=core \
// RUN:   -Xclang -analyzer-checker=debug.ExprInspection \
// RUN:   -Xclang -analyzer-checker=core,alpha.core.StdVariant


#include <variant>
 
void g() {
  std::variant<int, char> v = 25;
  std::variant<int, char> t = 'c';
  int a = std::get<0>(v);
  char c = std::get<1>(v);
  (void*)a;
  (void*)c;

}

void f() {
  std::variant<int, char> v = 25;
  int a = std::get<int>(v);
  char c = std::get<char>(v);
  (void*)a;
  (void*)c;

}

void h() {
  std::variant<int, char> v = 25;
  std::variant<int, char> t(v);
  int a = std::get<int> (t);
  char c = std::get<char> (t);
  (void*)a;
  (void*)c;

}
void i() {
  std::variant<int, char> v = 25;
  std::variant<int, char> t = 'c';
  t = v;
  int a = std::get<int> (t);
  char c = std::get<char> (t);
  (void*)a;
  (void*)c;
}


void j() {
  std::variant<int, char> v = 25;
  int a = std::get<int> (v);
  (void*)a;
  v = 'c';
  char c = std::get<char>(v);
  a = std::get<int>(v);
  (void*)a;
  (void*)c;
}