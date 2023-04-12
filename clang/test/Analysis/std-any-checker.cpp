// RUN: %clang %s -Xclang -verify --analyze \
// RUN:   -Xclang -analyzer-checker=core \
// RUN:   -Xclang -analyzer-checker=debug.ExprInspection \
// RUN:   -Xclang -analyzer-checker=core,alpha.core.StdAny

#include <any>

class DummyClass{
  public:
  void foo(){};
};

void nonInlined(std::any &a);
void nonInlinedConst(const std::any & a);

void inlined(std::any &a) {
  a = 5;
}

using any_t = std::any;
using any_tt = any_t;




void g() {
  std::any a = 5;
  int i = 0;
  i=  std::any_cast<int>(a);
  (void*)i;
}
