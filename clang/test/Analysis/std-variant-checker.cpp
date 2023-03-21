// RUN: %clang %s -Xclang -verify --analyze \
// RUN:   -Xclang -analyzer-checker=core \
// RUN:   -Xclang -analyzer-checker=debug.ExprInspection \
// RUN:   -Xclang -analyzer-checker=core,alpha.core.StdVariant


#include <variant>
#include <string>
#include <vector>
 
using vector_t = std::vector<int>;
using var_t = std::variant<int, char>;
using var_tt = var_t;

void g() {
  var_t vt = 'c';
  std::variant<int, char> v = 25;
  var_tt vtt = 55;

}

