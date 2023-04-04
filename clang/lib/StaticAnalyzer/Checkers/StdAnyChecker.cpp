//===- StdAnyChecker.cpp -------------------------------------*- C++ -*-==//
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
#include "llvm/ADT/FoldingSet.h"

#include <string>

using namespace clang;
using namespace ento;

REGISTER_MAP_WITH_PROGRAMSTATE(AnyHeldMap, const MemRegion*, QualType)

static bool isStdAny(const Type *Type) {
  auto Decl = Type->getAsRecordDecl();
  if (!Decl) {
    return false;
  } 
  return (Decl->getNameAsString() == std::string("any"))
          && Decl->isInStdNamespace();
}

const TemplateArgument& getFirstTemplateArgument(const CallEvent &Call);

class StdAnyChecker : public Checker<check::PreCall> {
  CallDescription AnyConstructorCall{{"std", "any"}};
  CallDescription AnyAsOp{{"std", "any", "operator="}};
  CallDescription AnyCast{{"std", "any_cast"}};
  BugType BadAnyType{this, "VariantCreated", "VariantCreated"};
  
  public:
  void checkPreCall(const CallEvent& Call, CheckerContext& C) const {
    if (AnyCast.matches(Call)) {
      handleAnyCall(Call, C);
    }
    llvm::errs() << "Any checker\n";

    bool isAnyConstructor = isa<CXXConstructorCall>(Call) &&
                                          AnyConstructorCall.matches(Call);
    bool isAnyAssignmentOperatorCall = isa<CXXMemberOperatorCall>(Call) &&
                                                      AnyAsOp.matches(Call);

    if ((isAnyConstructor || isAnyAssignmentOperatorCall) && Call.getNumArgs() == 1) {
      auto State = C.getState();
      llvm::errs() << "Any ctor w value\n";
      SVal thisSVal = [&]() {
        if (isAnyConstructor) {
          auto AsConstructorCall = dyn_cast<CXXConstructorCall>(&Call);
          return AsConstructorCall->getCXXThisVal();
        } else if (isAnyAssignmentOperatorCall) {
          auto AsMemberOpCall = dyn_cast<CXXMemberOperatorCall>(&Call);
          return AsMemberOpCall->getCXXThisVal();
        } else {
          llvm_unreachable(
                          "We must have an assignment operator or constructor");
        }
      }();
      auto argSVal = Call.getArgSVal(0);
      auto argQType = argSVal.getType(C.getASTContext()); 
      auto argQTypeWoPtr = argQType.getTypePtr()->getPointeeType();
      llvm::errs() << "Type assigned is: " << argQType.getAsString() << " " << argQTypeWoPtr.getAsString() << "\n";
      auto ThisMemRegion = thisSVal.getAsRegion();
      State = State->set<AnyHeldMap>(ThisMemRegion, argQTypeWoPtr);
      C.addTransition(State);
    }


    if (AnyConstructorCall.matches(Call)) {
        llvm::errs() << "Any ctor call found\n";
    }
  }

  private:
  void handleAnyCall(const CallEvent &Call, CheckerContext &C) const {
    auto State = C.getState();

    if (Call.getNumArgs() != 1) {
      return;
    }
    auto argSVal = Call.getArgSVal(0);
    llvm::errs() << "AnyCall: " << argSVal.getType(C.getASTContext()).getAsString() << '\n';
    //??
    auto ArgType = argSVal.getType(C.getASTContext()).getTypePtr()->getPointeeType().getTypePtr();
    if (!isStdAny(ArgType)) {
      return;
    }

    // get the type we are trying to get from any
    auto FirstTemplateArgument = getFirstTemplateArgument(Call);
    if (FirstTemplateArgument.getKind() != TemplateArgument::ArgKind::Type) {
      return;
    }
    auto TypeOut = FirstTemplateArgument.getAsType();

    auto AnyMemRegion = argSVal.getAsRegion();

    auto TypeStored = State->get<AnyHeldMap>(AnyMemRegion);
    if (*TypeStored == TypeOut) {
      llvm::errs() << "matches\n";
    } else {
      llvm::errs() << "not matches\n";
    }
  }

};


bool clang::ento::shouldRegisterStdAnyChecker(
    clang::ento::CheckerManager const &mgr) {
  return true;
}

void clang::ento::registerStdAnyChecker(clang::ento::CheckerManager &mgr) {
  mgr.registerChecker<StdAnyChecker>();
}