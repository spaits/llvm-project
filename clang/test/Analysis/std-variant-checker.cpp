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

void reasonAboutValueHeldInVariant() {
  std::variant<int, char> v = MAGIC_NUMBER;

  int numberFromVariant = std::get<int>(v);
  clang_analyzer_warnIfReached(); // expected-warning{{REACHABLE}}
  clang_analyzer_eval(numberFromVariant == MAGIC_NUMBER); // expected-warning{{TRUE}}

  DummyClass a = std::get<DummyClass>(v);
  clang_analyzer_warnIfReached(); // no-warning

}

void reasoningAboutGetIf() {
  std::variant<int, DummyClass> v = MAGIC_NUMBER;
  DummyClass* inVariant = std::get_if<DummyClass>(&v);
  clang_analyzer_eval(inVariant == nullptr); // expected-warning{{TRUE}}
  inVariant->f();
  clang_analyzer_warnIfReached(); // no-warning
}

void visit() {
  std::variant<int, DummyClass> v = MAGIC_NUMBER;

  int res = std::visit(overloaded{[](auto arg) {
                                        clang_analyzer_warnIfReached(); // no-warning
                                        return 0;
                                        },
                                  [](double arg) {
                                        clang_analyzer_warnIfReached(); // no-warning
                                        return 1; 
                                        },
                                  [](int arg) {
                                        clang_analyzer_warnIfReached(); // expected-warning {{REACHABLE}}
                                        return 2; 
                                        }},
                      v);
  clang_analyzer_dump(res);
  clang_analyzer_eval(res == 2); // expected-warning{{TRUE}}
}

