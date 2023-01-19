// RUN: %clang_analyze_cc1 -analyzer-checker=core,core.MainCall %s -verify

template<class... Types>
class variant {};

int main() {
    variant<int, char> v;
}

void g() {
  main(); // expected-warning{{VariantCreated [core.Variant]}}
}