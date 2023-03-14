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
  std::variant<int, char> v; 
  v = 0;
  int numFormVarinat = std::get<int>(v);
  int result = 25/ numFormVarinat; // expected-warning {{Division by zero [core.DivideZero]}}
  result++;
}