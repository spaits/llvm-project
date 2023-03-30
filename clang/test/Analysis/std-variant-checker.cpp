// RUN: %clang %s -Xclang -verify --analyze \
// RUN:   -Xclang -analyzer-checker=core \
// RUN:   -Xclang -analyzer-checker=debug.ExprInspection \
// RUN:   -Xclang -analyzer-checker=core,alpha.core.StdVariant


#include <variant>

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