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

REGISTER_MAP_WITH_PROGRAMSTATE(VariantHeldMap, const MemRegion*, QualType)

// Get the non pointer type behind any pointer type
// For example if we have an int*** we get int
static const Type* getPointeeType (const QualType& qt) {
  QualType Type = qt;
  QualType NextType = qt.getTypePtr()->getPointeeType();
  while (!NextType.isNull()) {
    Type = NextType;
    NextType = Type.getTypePtr()->getPointeeType();
  }
  return Type.getTypePtr();
}

static bool isCopyConstructorCallEvent (const CallEvent& Call) {
  auto ConstructorCall = dyn_cast<CXXConstructorCall>(&Call);
  if (!ConstructorCall) {
    return false;
  }
  auto ConstructorDecl = ConstructorCall->getDecl();
  if (!ConstructorDecl) {
    return false;
  }
  return ConstructorDecl->isCopyConstructor();
}

static bool isCopyAssignmentOperatorCall(const CallEvent& Call) {
  auto CopyAssignmentCall = dyn_cast<CXXMemberOperatorCall>(&Call);
  if (!CopyAssignmentCall) {
    return false;
  }
  auto CopyAssignmentDecl = CopyAssignmentCall->getDecl();
  if (!CopyAssignmentDecl) {
    return false;
  }
  auto AsMethodDecl = dyn_cast<CXXMethodDecl>(CopyAssignmentDecl);
  if (!AsMethodDecl) {
    return false;
  }
  return AsMethodDecl->isCopyAssignmentOperator();
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
    //Add type checking
    if (StdGet.matches(Call)) {
      handleStdGetCall(Call, C);
    }

    bool isVariantConstructor = isa<CXXConstructorCall>(Call) &&
                                          VariantConstructorCall.matches(Call);
    bool isVariantAssignmentOperatorCall = isa<CXXMemberOperatorCall>(Call) &&
                                                      VariantAsOp.matches(Call);

    if (isVariantConstructor || isVariantAssignmentOperatorCall) {
      if (Call.getNumArgs() != 1)
        return;
      SVal thisSVal = [&]() {
        if (isVariantConstructor) {
          auto AsConstructorCall = dyn_cast<CXXConstructorCall>(&Call);
          return AsConstructorCall->getCXXThisVal();
        } else if (isVariantAssignmentOperatorCall) {
          auto AsMemberOpCall = dyn_cast<CXXMemberOperatorCall>(&Call);
          return AsMemberOpCall->getCXXThisVal();
        } else {
          llvm_unreachable("We must have an assignment operator or constructor");
        }
      }();
      auto argQType = Call.getArgSVal(0).getType(C.getASTContext());
      const Type* typePtr = argQType.getTypePtr();

      if (isCopyConstructorCallEvent(Call) || isCopyAssignmentOperatorCall(Call)) {
        //Possible problem wit null type var
        auto argMemRegion = Call.getArgSVal(0).getAsRegion();
        if (!State->contains<VariantHeldMap>(argMemRegion))
          return;
        auto otherQType = State->get<VariantHeldMap>(argMemRegion);
        Call.getArgSVal(0).dump();
        State = State->set<VariantHeldMap>(thisSVal.getAsRegion(), *otherQType);
      } else {
        auto woPointer = typePtr->getPointeeType();
        State = State->set<VariantHeldMap>(thisSVal.getAsRegion(), woPointer);
      }
      C.addTransition(State);
      return;
    }
  }

  void handleStdGetCall(const CallEvent &Call, CheckerContext &C) const {

    auto State = Call.getState();
    auto TypeOut = getFirstTemplateArgument(Call);
    auto TypeStored = State->get<VariantHeldMap>(Call.getArgSVal(0).getAsRegion());

    if (!TypeStored) {
      return;
    } 

    auto GetType = [&]() {
    switch (TypeOut.getKind()) {
      case TemplateArgument::ArgKind::Type:
        return TypeOut.getAsType();
      case TemplateArgument::ArgKind::Integral:
        return getNthTmplateTypeArgFromVariant(
          getPointeeType(Call.getArgSVal(0).getType(C.getASTContext())),
          TypeOut.getAsIntegral().getSExtValue());
      default:
        llvm_unreachable("An std::get's first template argument can only be a type or an integral");
    }}();

    bool matches = GetType == *TypeStored;

    if (matches) {
      return;
    }

    ExplodedNode* ErrNode = C.generateNonFatalErrorNode();
    if (!ErrNode)
      return;
    llvm::SmallString<128> Str;
    llvm::raw_svector_ostream OS(Str);
    OS << "Variant held a(n) " << TypeStored->getAsString() << " not a(n) " << GetType.getAsString();
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