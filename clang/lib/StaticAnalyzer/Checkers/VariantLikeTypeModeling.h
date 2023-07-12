//===- VariantLikeModeling.h -------------------------------------*- C++ -*-==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_LIB_STATICANALYZER_CHECKER_VARIANTLIKETYPEMODELING_H
#define LLVM_CLANG_LIB_STATICANALYZER_CHECKER_VARIANTLIKETYPEMODELING_H

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/ADT/FoldingSet.h"
#include <numeric>

namespace clang {
namespace ento {
namespace variant_modeling {

// The implementation of all these functions can be found in the
// StdVariantChecker.cpp file under the same directory as this file.
CallEventRef<> getCaller(const CallEvent &Call, CheckerContext &C);
const TemplateArgument &getFirstTemplateArgument(const CallEvent &Call);
bool isObjectOf(QualType t, QualType to);
bool isCopyConstructorCall(const CallEvent &Call);
bool isCopyAssignmentCall(const CallEvent &Call);
bool isMoveAssignmentCall(const CallEvent &Call);
bool isMoveConstructorCall(const CallEvent &Call);
bool isStdType(const Type *Type, const std::string &TypeName);
bool isStdVariant(const Type *Type);
bool isStdAny(const Type *Type);
bool calledFromSystemHeader(const CallEvent &Call, CheckerContext &C);

// When invalidating regions we also have to follow that with our data
// storages in the program state.
template <class T, class S>
ProgramStateRef
removeInformationStoredForDeadInstances(const CallEvent *Call,
                                        ProgramStateRef State,
                                        ArrayRef<const MemRegion *> Regions) {
  // If we do not know anything about the call we shall not continue.
  if (!Call) {
    return State;
  }

  // If the call is coming from a system header it is implementation detail.
  // We should not take it into consideration.
  if (Call->isInSystemHeader()) {
    return State;
  }

  // Remove the information we know about the invalidate region.
  // It is not relevant anymore.
  State = std::accumulate(
      Regions.begin(), Regions.end(), State,
      [](ProgramStateRef State, const MemRegion *CurrentMemRegion) {
        if (State->contains<T>(CurrentMemRegion)) {
          State = State->remove<T>(CurrentMemRegion);
        }
        if (State->contains<S>(CurrentMemRegion)) {
          State = State->remove<S>(CurrentMemRegion);
        }
        return State;
      });
  return State;
}

template <class T>
void bindVariableFromVariant(const Expr *RHSExpr, const SVal &LHSVal,
                             const CallDescription &StdGet, CheckerContext &C) {
  auto LHSLoc = dyn_cast<Loc>(LHSVal);
  if (!LHSLoc) {
    return;
  }
  // If the right hand site expression is a cast then we want go get the casted
  // expression.
  auto RHSCall = dyn_cast<CallExpr>(RHSExpr);
  auto RHSCast = dyn_cast<CastExpr>(RHSExpr);
  while (!RHSCall && RHSCast) {
    auto SubExpr = RHSCast->getSubExpr();
    if (!SubExpr) {
      return;
    }
    RHSCall = dyn_cast<CallExpr>(SubExpr);
    RHSCast = dyn_cast<CastExpr>(SubExpr);
  }

  // Check if there is really a function call on the right.
  if (!RHSCall) {
    return;
  }

  // Check wether the interesting function is called
  if (!StdGet.matchesAsWritten(*RHSCall)) {
    return;
  }

  // Both std::get and std::any_cast have one argument
  if (RHSCall->getNumArgs() != 1) {
    return;
  }

  // We know that at this point we assign value to the LValue on the left from
  // and a call we want.

  // Now our goal is to get the SVal symbolizing the argument.
  // With the help of that the information stored in the
  // program state can be accessed.

  // Get the first argument of the function
  auto Arg = RHSCall->getArg(0);
  if (!Arg) {
    return;
  }

  // Get the declaration of the instance
  auto ArgDeclRef = dyn_cast<DeclRefExpr>(Arg);
  if (!ArgDeclRef) {
    return;
  }
  auto ActualArgDecl = ArgDeclRef->getDecl();
  if (!ActualArgDecl) {
    return;
  }
  auto VDecl = dyn_cast<VarDecl>(ActualArgDecl);

  // Get the argument SVal from store manager with the declaration.
  auto ArgSVal =
      C.getStoreManager().getLValueVar(VDecl, C.getLocationContext());

  // In ArgMemRegion we have the memory region of the calls argument.
  // The call in our case is an std::get with an std::variant argument
  // or an std::any_case with an std::any argument.
  auto ArgMemRegion = ArgSVal.getAsRegion();
  if (!ArgMemRegion) {
    return;
  }

  auto State = C.getState();

  // We get the value held in std::variant or std::any.
  auto SValGet = State->get<T>(ArgMemRegion);
  if (!SValGet) {
    return;
  }

  // Remove the original binding which was made by inlining the implementation
  // of the class
  State = State->killBinding(*LHSLoc);

  // Replace it with our non implementation dependent information
  State = State->bindLoc(*LHSLoc, *SValGet, C.getLocationContext());

  C.addTransition(State);
}

template <class T>
// We handle the retrieving of objects from an std::variant or std::any
void bindFromVariant(const BinaryOperator *BinOp, CheckerContext &C,
                     const CallDescription &StdGet) {
  // First we check if the right hand site of the call is matches the
  // CallDescription we gave as argument.
  if (!BinOp->isAssignmentOp()) {
    return;
  }

  // Now we get the memory region for the LValue we assign the result of
  // std::get or std::any_cast call to.
  auto LeftHandExpr = BinOp->getLHS();
  auto LHSVal = C.getSVal(LeftHandExpr);

  const Expr *RHSExpr = BinOp->getRHS();
  if (!RHSExpr) {
    return;
  }
  bindVariableFromVariant<T>(RHSExpr, LHSVal, StdGet, C);
}

template <class T>
void bindFromVariant(const DeclStmt *DeclS, CheckerContext &C,
                     const CallDescription &StdGet) {
  const Decl *Declaration = DeclS->getSingleDecl();
  if (!Declaration) {
    return;
  }
  const auto VariableDeclaration = dyn_cast<VarDecl>(Declaration);

  if (!VariableDeclaration) {
    return;
  }

  // Get the SVal of the declared variable
  auto State = C.getState();
  const LocationContext *CurrentLocation = C.getLocationContext();
  if (!CurrentLocation) {
    return;
  }

  SVal DeclaredVariable =
      State->getLValue(VariableDeclaration, CurrentLocation);
  auto DecVarLocation = dyn_cast<Loc>(DeclaredVariable);
  if (!DecVarLocation) {
    return;
  }

  // get the SVal returned by the initial expression
  const Expr *RHSExpr = VariableDeclaration->getInit();
  if (!RHSExpr) {
    return;
  }

  bindVariableFromVariant<T>(RHSExpr, DeclaredVariable, StdGet, C);
}

template <class T, class U>
void handleConstructorAndAssignment(const CallEvent &Call, CheckerContext &C,
                                    const SVal &ThisSVal) {
  ProgramStateRef State = Call.getState();

  auto ArgSVal = Call.getArgSVal(0);
  auto ThisRegion = ThisSVal.getAsRegion();
  auto ArgMemRegion = ArgSVal.getAsRegion();

  // Make changes to the state according to type of constructor/assignment
  State = [&]() {
    bool IsCopy = isCopyConstructorCall(Call) || isCopyAssignmentCall(Call);
    bool IsMove = isMoveConstructorCall(Call) || isMoveAssignmentCall(Call);

    // First we handle copy and move operations
    if (IsCopy || IsMove) {
      // If the argument of a copy constructor or assignment is unknown then
      // we will not know the argument of the copied to object.
      bool OtherQTypeKnown = State->contains<T>(ArgMemRegion);
      bool OtherSValKnown = State->contains<U>(ArgMemRegion);

      const QualType *OtherQType;
      if (OtherQTypeKnown) {
        OtherQType = State->get<T>(ArgMemRegion);
      } else {
        return State->contains<T>(ThisRegion) ? State->remove<T>(ThisRegion)
                                              : State;
      }

      const SVal *OtherSVal;
      if (OtherSValKnown) {
        OtherSVal = State->get<U>(ArgMemRegion);
      } else {
        return State->contains<U>(ThisRegion) ? State->remove<U>(ThisRegion)
                                              : State;
      }

      // When move semantics is used we can only know that the moved from
      // object must be in a destructible state. Other usage of the object
      // than destruction is undefined.
      if (IsMove) {
        State = State->contains<T>(ArgMemRegion)
                    ? State->remove<T>(ArgMemRegion)
                    : State;
        State = State->contains<U>(ArgMemRegion)
                    ? State->remove<U>(ArgMemRegion)
                    : State;
      }
      State = State->set<U>(ThisRegion, *OtherSVal);
      return State->set<T>(ThisRegion, *OtherQType);
    }
    // Then the other constructor/assignment where the argument is the new
    // object held by the std::variant or std::any
    auto ArgQType = ArgSVal.getType(C.getASTContext());
    const Type *ArgTypePtr = ArgQType.getTypePtr();
    auto AsMemRegLoc = dyn_cast<Loc>(ArgSVal);

    SVal ToStore =
        C.getStoreManager().getBinding(C.getState()->getStore(), *AsMemRegLoc);
    State = State->set<U>(ThisRegion, ToStore);

    QualType WoPointer = ArgTypePtr->getPointeeType();
    return State->set<T>(ThisRegion, WoPointer);
  }();

  if (State) {
    C.addTransition(State);
  } else {
    C.addTransition(Call.getState()->remove<T>(ThisRegion));
  }
}

} // namespace variant_modeling
} // namespace ento
} // namespace clang

#endif // LLVM_CLANG_LIB_STATICANALYZER_CHECKER_VARIANTLIKETYPEMODELING_H