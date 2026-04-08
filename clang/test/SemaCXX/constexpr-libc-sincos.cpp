// RUN: %clang_cc1 -std=c++23 -fsyntax-only %s -triple=x86_64-linux-gnu

static_assert(__builtin_sin(0.0) == 0.0);
static_assert(__builtin_cos(0.0) == 1.0);
