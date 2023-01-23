//===- StdVariantChecker.cpp -------------------------------------*- C++ -*-==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

class StdVariantChecker : public Checker<check::PreCall> {
    CallDescription VariantConstructorCall{{"std", "variant"}, 0, 0};
    BugType VariantCreated{this, "VariantCreated", "VariantCreated"};

    public:
    void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
      if (!isa<CXXConstructorCall>(Call))
        return;
      if (!VariantConstructorCall.matches(Call))
        return;

      ExplodedNode* ErrNode = C.generateNonFatalErrorNode();
      if (!ErrNode)
        return;
      llvm::SmallString<128> Str;
      llvm::raw_svector_ostream OS(Str);
      OS << "Variant Created";
      auto R = std::make_unique<PathSensitiveBugReport>(
          VariantCreated, OS.str(), ErrNode);
      C.emitReport(std::move(R));
    }
};

bool clang::ento::shouldRegisterStdVariantChecker(
    clang::ento::CheckerManager const &mgr) {
  return true;
}

void clang::ento::registerStdVariantChecker(clang::ento::CheckerManager &mgr) {
  mgr.registerChecker<StdVariantChecker>();
}