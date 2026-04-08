//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

// REQUIRES: clang
// UNSUPPORTED: c++03, c++11, c++14, c++17, c++20, windows

#include <cmath>

static_assert(std::sin(0.0) == 0.0);
static_assert(std::cos(0.0) == 1.0);

int main(int, char**) { return 0; }
