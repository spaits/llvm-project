//===- StdAnyChecker.cpp -------------------------------------*- C++ -*----===//
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

#include "VariantLikeTypeModeling.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace variant_modeling;

REGISTER_MAP_WITH_PROGRAMSTATE(AnyHeldTypeMap, const MemRegion *, QualType)
REGISTER_MAP_WITH_PROGRAMSTATE(AnyHeldMap, const MemRegion *, SVal)

class StdAnyChecker : public Checker<check::PreCall, check::RegionChanges,
                                     check::PostStmt<BinaryOperator>,
                                     check::PostStmt<DeclStmt>> {
  CallDescription AnyConstructor{{"std", "any", "any"}};
  CallDescription AnyAsOp{{"std", "any", "operator="}};
  CallDescription AnyReset{{"std", "any", "reset"}, 0, 0};
  CallDescription AnyCast{{"std", "any_cast"}, 1, 1};

  BugType BadAnyType{this, "BadAnyType", "BadAnyType"};
  BugType NullAnyType{this, "NullAnyType", "NullAnyType"};

public:
  void checkPostStmt(const BinaryOperator *BinOp, CheckerContext &C) const {
    bindFromVariant<AnyHeldMap>(BinOp, C, AnyCast);
  }
  void checkPostStmt(const DeclStmt *DeclS, CheckerContext &C) const {
    bindFromVariant<AnyHeldMap>(DeclS, C, AnyCast);
  }

  ProgramStateRef
  checkRegionChanges(ProgramStateRef State,
                     const InvalidatedSymbols *Invalidated,
                     ArrayRef<const MemRegion *> ExplicitRegions,
                     ArrayRef<const MemRegion *> Regions,
                     const LocationContext *LCtx, const CallEvent *Call) const {
    return removeInformationStoredForDeadInstances<AnyHeldTypeMap, AnyHeldMap>(
        Call, State, Regions);
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    // Do not take implementation details into consideration
    if (calledFromSystemHeader(Call, C)) {
      return;
    }

    if (AnyCast.matches(Call)) {
      handleAnyCastCall(Call, C);
      return;
    }

    if (AnyReset.matches(Call)) {
      auto AsMemberCall = dyn_cast<CXXMemberCall>(&Call);
      if (!AsMemberCall) {
        return;
      }
      auto ThisMemRegion = AsMemberCall->getCXXThisVal().getAsRegion();
      if (!ThisMemRegion) {
        return;
      }
      setNullTypeAny(ThisMemRegion, C);
      return;
    }

    bool IsAnyConstructor =
        isa<CXXConstructorCall>(Call) && AnyConstructor.matches(Call);
    bool IsAnyAssignmentOperatorCall =
        isa<CXXMemberOperatorCall>(Call) && AnyAsOp.matches(Call);

    if (IsAnyConstructor || IsAnyAssignmentOperatorCall) {
      auto State = C.getState();
      SVal ThisSVal = [&]() {
        if (IsAnyConstructor) {
          auto AsConstructorCall = dyn_cast<CXXConstructorCall>(&Call);
          return AsConstructorCall->getCXXThisVal();
        } else if (IsAnyAssignmentOperatorCall) {
          auto AsMemberOpCall = dyn_cast<CXXMemberOperatorCall>(&Call);
          return AsMemberOpCall->getCXXThisVal();
        } else {
          llvm_unreachable(
              "We must have an assignment operator or constructor");
        }
      }();

      // default constructor call
      // in this case the any holds a null type
      if (Call.getNumArgs() == 0) {
        auto ThisMemRegion = ThisSVal.getAsRegion();
        setNullTypeAny(ThisMemRegion, C);
        return;
      }

      if (Call.getNumArgs() != 1) {
        return;
      }

      handleConstructorAndAssignment<AnyHeldTypeMap, AnyHeldMap>(Call, C,
                                                                 ThisSVal);
      return;
    }
  }

private:
  // When an std::any is rested or default constructed it has a null type.
  // We represent it by storing a null QualType.
  void setNullTypeAny(const MemRegion *Mem, CheckerContext &C) const {
    auto State = C.getState();
    State = State->set<AnyHeldTypeMap>(Mem, QualType{});
    C.addTransition(State);
  }

  // this function name is terrible
  void handleAnyCastCall(const CallEvent &Call, CheckerContext &C) const {
    auto State = C.getState();

    // std::any_cast should have only one template argument
    if (Call.getNumArgs() != 1) {
      return;
    }
    auto ArgSVal = Call.getArgSVal(0);

    // The argument is aether a const reference or a right value reference
    //  We need the type referred
    auto ArgType = ArgSVal.getType(C.getASTContext())
                       .getTypePtr()
                       ->getPointeeType()
                       .getTypePtr();
    if (!isStdAny(ArgType)) {
      return;
    }

    auto AnyMemRegion = ArgSVal.getAsRegion();

    if (!State->contains<AnyHeldTypeMap>(AnyMemRegion)) {
      return;
    }
    // get the type we are trying to get from any
    auto FirstTemplateArgument = getFirstTemplateArgument(Call);
    if (FirstTemplateArgument.getKind() != TemplateArgument::ArgKind::Type) {
      return;
    }

    auto TypeOut = FirstTemplateArgument.getAsType();
    auto TypeStored = State->get<AnyHeldTypeMap>(AnyMemRegion);

    // Report when we try to use std::any_cast on an std::any that held a null
    // type
    if (TypeStored->isNull()) {
      ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
      if (!ErrNode)
        return;
      llvm::SmallString<128> Str;
      llvm::raw_svector_ostream OS(Str);
      OS << "std::any " << AnyMemRegion->getDescriptiveName() << " is empty.";
      auto R = std::make_unique<PathSensitiveBugReport>(NullAnyType, OS.str(),
                                                        ErrNode);
      C.emitReport(std::move(R));
      return;
    }

    // Check if the right type is being accessed
    // There is spacial case for object types.
    if (*TypeStored == TypeOut || isObjectOf(TypeOut, *TypeStored)) {
      return;
    }

    // Report when the type we want to get out of std::any is wrong
    ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
    if (!ErrNode)
      return;
    llvm::SmallString<128> Str;
    llvm::raw_svector_ostream OS(Str);
    OS << "std::any " << AnyMemRegion->getDescriptiveName() << " held a(n) "
       << TypeStored->getAsString() << " not a(n) " << TypeOut.getAsString();
    auto R =
        std::make_unique<PathSensitiveBugReport>(BadAnyType, OS.str(), ErrNode);
    C.emitReport(std::move(R));
    return;
  }
};

bool clang::ento::shouldRegisterStdAnyChecker(
    clang::ento::CheckerManager const &mgr) {
  return true;
}

void clang::ento::registerStdAnyChecker(clang::ento::CheckerManager &mgr) {
  mgr.registerChecker<StdAnyChecker>();
}