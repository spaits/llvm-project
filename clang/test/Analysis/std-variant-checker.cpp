// RUN: %clang %s -Xclang -verify --analyze \
// RUN:   -Xclang -analyzer-checker=core \
// RUN:   -Xclang -analyzer-checker=debug.ExprInspection \
// RUN:   -Xclang -analyzer-checker=core,alpha.core.StdVariant


#include <variant>
#include <string>
#include <vector>
 
using vector_t = std::vector<int>;

void g() {
  std::variant<std::string, vector_t, char> var6 {std::in_place_index<1>, 4, 42};
  var6 = 'c';
}

