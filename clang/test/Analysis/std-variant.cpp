// RUN: %clang %s -Xclang -verify --analyze \
// RUN:   -Xclang -analyzer-checker=core \
// RUN:   -Xclang -analyzer-checker=debug.ExprInspection

#include <variant>

struct DummyClass {
    int i;
    char c;
};

void clang_analyzer_eval(int);
template <typename T>
constexpr void clang_analyzer_dump(T) {}

void reasonAboutVariableHeldInVariant() {
    std::variant<int, char, DummyClass> variant;

    variant = 15;
    int integerFromVariant = std::get<int>(variant);
    clang_analyzer_dump(integerFromVariant);
    clang_analyzer_eval(integerFromVariant == 15); // expected-warning{{TRUE}}


    variant = 'c';
    char charFromVariant = std::get<char>(variant);
    clang_analyzer_dump(charFromVariant);
    clang_analyzer_eval(charFromVariant == 'c');

    variant = DummyClass{15,'c'};
    DummyClass dcFromVariant = std::get<DummyClass>(variant);
    int integerFromVariant2 = dcFromVariant.i;
    char charFromVariant2 = dcFromVariant.c;
    clang_analyzer_dump(integerFromVariant2);
    clang_analyzer_eval(integerFromVariant2 == 15);
    clang_analyzer_dump(charFromVariant2);
    clang_analyzer_eval(charFromVariant2 == 'c');
}