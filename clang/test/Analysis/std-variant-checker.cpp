// RUN: %clang %s -Xclang -verify --analyze \
// RUN:   -Xclang -analyzer-checker=core \
// RUN:   -Xclang -analyzer-checker=debug.ExprInspection

#include <variant>
#include <string>
#define MAGIC_NUMBER 21

class DummyClass {
  public:
  void f() {};
};

void clang_analyzer_eval(int);
void clang_analyzer_warnIfReached();
template <typename T>
constexpr void clang_analyzer_dump(T) {}


void g() {
  clang_analyzer_warnIfReached();  // expected-warning{{REACHABLE}}
  std::variant<int, char> v; 
  clang_analyzer_warnIfReached();  // expected-warning{{REACHABLE}}
  v = 0;
  clang_analyzer_warnIfReached();  // expected-warning{{REACHABLE}}
  int numFormVarinat = std::get<int>(v);
  clang_analyzer_warnIfReached();  // expected-warning{{REACHABLE}}
  int result = 25/ numFormVarinat;
  clang_analyzer_warnIfReached(); // no-warning
  result++;
}

