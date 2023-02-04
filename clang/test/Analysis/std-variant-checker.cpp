// RUN: %clang %s -Xclang -verify --analyze \
// RUN:   -Xclang -analyzer-checker=core \
// RUN:   -Xclang -analyzer-checker=debug.ExprInspection \
// RUN:   -Xclang -analyzer-checker=alpha.core.StdVariant

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

template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

void g() {
  std::variant<int, char> v; // expected-warning{{Variant Created [alpha.core.StdVariant]}}
}

void reasonAboutValueHeld() {
  std::variant<int, DummyClass> v = MAGIC_NUMBER;
  int valueFromVariant = std::get<int> (v);
  clang_analyzer_eval(valueFromVariant == MAGIC_NUMBER); // expected-warning{{TRUE}}
}

void reasonAboutPrimitiveTypes() {
  std::variant<int, DummyClass> v1 = MAGIC_NUMBER;
  std::variant<int, std::string> v2 = MAGIC_NUMBER;

  int fromVariant1 = std::get<int>(v1);
  clang_analyzer_warnIfReached(); // expected-warning{{REACHABLE}}
  clang_analyzer_eval(fromVariant1 == MAGIC_NUMBER); // expected-warning{{TRUE}}

  int fromVariant2 = std::get<int>(v2);
  clang_analyzer_warnIfReached(); // expected-warning{{REACHABLE}}
  clang_analyzer_eval(fromVariant2 == MAGIC_NUMBER); // expected-warning{{TRUE}}

  DummyClass fromWrong = std::get<DummyClass>(v1);
  clang_analyzer_warnIfReached(); // no-warning
}
