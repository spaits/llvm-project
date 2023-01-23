// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.core.StdVariant %s -verify

#include "Inputs/variant.h"

void g() {
  std::variant<int, char> v; // expected-warning{{Variant Created [alpha.core.StdVariant]}}
}