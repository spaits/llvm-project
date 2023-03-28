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
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/ADT/FoldingSet.h"

using namespace clang;
using namespace ento;

REGISTER_MAP_WITH_PROGRAMSTATE(VariantHeldMap, SymbolRef, QualType);

// Get the non pointer type behind any pointer type
// For example if we have an int*** we get int
static const Type* getPointeeType (const QualType& qt) {
  const Type* PrevTypePtr = qt.getTypePtr();
  const Type* TypePtr = PrevTypePtr->getPointeeType().getTypePtr();
  while (TypePtr) {
    PrevTypePtr = TypePtr;
    TypePtr = PrevTypePtr->getPointeeType().getTypePtr();
  }
  return PrevTypePtr;
}

class StdVariantChecker : public Checker<check::PreCall> {
  CallDescription VariantConstructorCall{{"std", "variant"}};
  CallDescription VariantAsOp{{"std", "variant", "operator="}};
  CallDescription StdGet{{"std", "get"}};
  BugType VariantCreated{this, "VariantCreated", "VariantCreated"};

  public:
  ArrayRef<TemplateArgument> getTemplateArgsFromVariant(const Type* VariantType) const {
    auto TempSpecType = VariantType->getAs<TemplateSpecializationType>();
    assert(TempSpecType && "We are in a variant instance. It must be a template specialization!");
    return TempSpecType->template_arguments();
  }

  const TemplateArgument& getFirstTemplateArgument(const CallEvent &Call) const {
    const CallExpr* CE = cast<CallExpr>(Call.getOriginExpr());
    const FunctionDecl* FD = CE->getDirectCallee();
    assert(1 <= FD->getTemplateSpecializationArgs()->asArray().size() &&
              "std::get should have at least 1 template argument!");
    return FD->getTemplateSpecializationArgs()->asArray()[0];
  }

  QualType getNthTmplateTypeArgFromVariant(const Type* varType, unsigned i) const {
    //TODO
    return getTemplateArgsFromVariant(varType)[i].getAsType();
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    auto State = Call.getState();
    if (StdGet.matches(Call)) {
      auto TypeOut = getFirstTemplateArgument(Call);
      auto TypeStored = State->get<VariantHeldMap>(Call.getArgSVal(0).getAsLocSymbol());

      if (!TypeStored) {
        return;
      } 

      bool matches = true;
      switch (TypeOut.getKind()) {
        case TemplateArgument::ArgKind::Type:
          matches = TypeOut.getAsType() == *(TypeStored);
          break;
        case TemplateArgument::ArgKind::Integral:
          auto variantNthArg = getNthTmplateTypeArgFromVariant(
            Call.getArgSVal(0).getType(C.getASTContext()).getTypePtr()->getPointeeType().getTypePtr(),
            TypeOut.getAsIntegral().getSExtValue());
          matches = variantNthArg == *(TypeStored);
          llvm::errs() << "Getting w int\n";
          break;
      }

      if (matches) {
      } else {
        ExplodedNode* ErrNode = C.generateNonFatalErrorNode();
        if (!ErrNode)
          return;
        llvm::SmallString<128> Str;
        llvm::raw_svector_ostream OS(Str);
        OS << "Variant held a(n) " << TypeStored->getAsString() << " not a(n)";
        auto R = std::make_unique<PathSensitiveBugReport>(
          VariantCreated, OS.str(), ErrNode);
        C.emitReport(std::move(R));
      }
      
    }

    bool isVariantConstructor = isa<CXXConstructorCall>(Call) &&
                                          VariantConstructorCall.matches(Call);
    bool isVariantAssignmentOperatorCall = isa<CXXMemberOperatorCall>(Call) &&
                                                      VariantAsOp.matches(Call);

    if (isVariantConstructor || isVariantAssignmentOperatorCall) {
      if (Call.getNumArgs() != 1)
        return;
      SVal thisSVal;
      if (isVariantConstructor) {
        auto AsConstructorCall = dyn_cast<CXXConstructorCall>(&Call);
        thisSVal = AsConstructorCall->getCXXThisVal();
      } else if (isVariantAssignmentOperatorCall) {
        auto AsMemberOpCall = dyn_cast<CXXMemberOperatorCall>(&Call);
        thisSVal = AsMemberOpCall->getCXXThisVal();
      } else {
        llvm_unreachable("AAA");
      }
      auto origQT = Call.getArgSVal(0).getType(C.getASTContext());
      const Type* typePtr = origQT.getTypePtr();
      auto woPointer = typePtr->getPointeeType();
      State = State->set<VariantHeldMap>(thisSVal.getAsLocSymbol(), woPointer);
      C.addTransition(State);
      return;
    }
  }
};

bool clang::ento::shouldRegisterStdVariantChecker(
    clang::ento::CheckerManager const &mgr) {
  return true;
}

void clang::ento::registerStdVariantChecker(clang::ento::CheckerManager &mgr) {
  mgr.registerChecker<StdVariantChecker>();
}