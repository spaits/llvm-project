//===- StdVariantChecker.cpp -------------------------------------*- C++ -*-==//
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

namespace clang {
namespace ento {
namespace variant_modeling {


// The implementation of all these functions can be found in the
// StdVariantChecker.cpp file under the same directory as this file.
const TemplateArgument& getFirstTemplateArgument(const CallEvent &Call);
bool isObjectOf(QualType t, QualType to);
bool isCopyConstructorCallEvent (const CallEvent& Call);
bool isCopyAssignmentOperatorCall(const CallEvent& Call);
bool isMoveAssignemntCall(const CallEvent &Call);
bool isMoveConstructorCall(const CallEvent &Call);
CallEventRef<> getCaller(const CallEvent &Call, CheckerContext &C);
bool isStdType(const Type *Type, const std::string &TypeName);
bool isStdVariant(const Type *Type);
bool isStdAny(const Type *Type);

template <class T>

// We handle the retrieving of objects from an std::variant or std::any
void bindFromVariant(const BinaryOperator *BinOp,
                     CheckerContext &C,
                     const CallDescription &StdGet) {
  // First we check if the right hand site of the call is matches the
  // CallDescription we gave as argument.
  if (!BinOp->isAssignmentOp()) {
    return;
  }

  auto RHSExpr = BinOp->getRHS();

  if (!RHSExpr) {
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

  if (!RHSCall) {
    return;
  }

  if (!StdGet.matchesAsWritten(*RHSCall)) {
    return;
  }

  //Both std::get and std::any_cast have one argument
  if (RHSCall->getNumArgs() != 1) {
    return;
  }
  // We know that at this point we assign value to the LValue on the left from
  // and a call we want.

  auto Arg = RHSCall->getArg(0);
  if (!Arg) {
    return;
  }
  auto ArgDeclRef = dyn_cast<DeclRefExpr>(Arg);
  auto VDecl = dyn_cast<VarDecl>(ArgDeclRef->getDecl());


  auto ArgSVal = C.getStoreManager().getLValueVar(VDecl, C.getLocationContext());//C.getSVal(Arg);
  // In ArgMemRegion we have the memory region of the calls argument.
  // The call in our case is an std::get with an std::variant argument
  // or an std::any_case with an std::any argument.
  auto ArgMemRegion = ArgSVal.getAsRegion();
  if (!ArgMemRegion) {
    return;
  }

  auto State = C.getState();
  //add check if
  //  We get the value held in std::variant or std::any.
  auto SValGet = State->get<T>(ArgMemRegion);
  if (!SValGet) {
    return;
  }

  // Now we get the memory region for the LValue we assign the result of
  // std::get or std::any_cast call to.
  auto LeftHandExpr = BinOp->getLHS();
  auto LHSSVal = C.getSVal(LeftHandExpr);
  auto LHSLoc = dyn_cast<Loc>(LHSSVal);
  if (!LHSLoc) {
    return;
  }

  // Remove the original binding which was made by inlining the implementation
  // of the class
  State = State->killBinding(*LHSLoc);

  // Replace it with our non implementation dependent information
  State = State->bindLoc(*LHSLoc, *SValGet, C.getLocationContext());

  C.addTransition(State);
}

template <class T, class U>
void handleConstructorAndAssignment(const CallEvent &Call,
                                      CheckerContext &C,
                                      const SVal &ThisSVal) {
  ProgramStateRef State = Call.getState(); // check

  auto ArgSVal = Call.getArgSVal(0);
  auto ThisRegion = ThisSVal.getAsRegion();
  
  auto ArgMemRegion = Call.getArgSVal(0).getAsRegion();

  State = [&]() {
    bool IsCopy = isCopyConstructorCallEvent(Call) ||
                                          isCopyAssignmentOperatorCall(Call);
    bool IsMove = isMoveConstructorCall(Call) || isMoveAssignemntCall(Call);

    if (IsCopy || IsMove) {
      // If the argument of a copy constructor or assignment is unknown then
      // we will not know the argument of the copied to object.
      bool OtherQTypeKnown = State->contains<T>(ArgMemRegion);
      bool OtherSValKnown = State->contains<U>(ArgMemRegion);

      const QualType *OtherQType;
      if (OtherQTypeKnown) {
        OtherQType = State->get<T>(ArgMemRegion);
      } else {
        return State->remove<T>(ThisRegion);
      }

      const SVal *OtherSVal;
      if (OtherSValKnown) {
        OtherSVal =  State->get<U>(ArgMemRegion);
      } else {
        return State->remove<U>(ThisRegion);
      }

      // When move semantics is used we can only know that the moved from
      // object must be in a destructible state. Other usage of the object
      // than destruction is undefined.
      if (IsMove) {
        State = State->remove<T>(ArgMemRegion);
        State = State->remove<U>(ArgMemRegion);
      }
      State = State->set<U>(ThisRegion, *OtherSVal);
      return State->set<T>(ThisRegion, *OtherQType);
    }
  auto ArgQType = ArgSVal.getType(C.getASTContext());
  const Type* ArgTypePtr = ArgQType.getTypePtr();

    auto AsMemRegLoc = dyn_cast<Loc>(ArgSVal);

    SVal ToStore;

    //if (AsMemRegLoc) {
    ToStore = C.getStoreManager().getBinding(C.getState()->getStore(), *AsMemRegLoc);
    State = State->set<U>(ThisRegion, ToStore);
    //}

    QualType WoPointer = ArgTypePtr->getPointeeType();
    return State->set<T>(ThisRegion, WoPointer);
  }();

  if (State) {
    C.addTransition(State);
  } else {
    C.addTransition(Call.getState()->remove<T>(ThisRegion));
  }
}

} //namespace variant_modeling
} //namespace ento
} //namespace clang

#endif // LLVM_CLANG_LIB_STATICANALYZER_CHECKER_VARIANTLIKETYPEMODELING_H