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
#include "llvm/ADT/FoldingSet.h"

#include <string>
#include "VariantLikeTypeModeling.h"

using namespace clang;
using namespace ento;
using namespace variant_modeling;

REGISTER_MAP_WITH_PROGRAMSTATE(VariantHeldMap, const MemRegion*, QualType)
REGISTER_MAP_WITH_PROGRAMSTATE(VariantMap, const MemRegion*, SVal)

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
namespace clang {
namespace ento {
namespace variant_modeling {

CallEventRef<> getCaller(const CallEvent &Call, CheckerContext &C) {
  auto CallLocationContext = Call.getLocationContext();
  if (!CallLocationContext) {
    return CallEventRef<>(nullptr); 
  }

  if (CallLocationContext->inTopFrame()) {
    return CallEventRef<>(nullptr); 
  }
  auto CallStackFrameContext = CallLocationContext->getStackFrame();
  if (!CallStackFrameContext) {
    return CallEventRef<>(nullptr);
  }

  CallEventManager &CEMgr = C.getState()->getStateManager().getCallEventManager();
  return CEMgr.getCaller(CallStackFrameContext, C.getState());
}

bool isObjectOf(QualType t, QualType to) {
  QualType canonicalTypeT = t.getCanonicalType();
  QualType canonicalTypeTo = to.getCanonicalType();
  return canonicalTypeTo == canonicalTypeT && canonicalTypeTo->isObjectType();
}

bool isCopyConstructorCallEvent (const CallEvent& Call) {
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

bool isCopyAssignmentOperatorCall(const CallEvent& Call) {
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

bool isMoveConstructorCall(const CallEvent &Call) {
  auto ConstructorCall = dyn_cast<CXXConstructorCall>(&Call);
  if (!ConstructorCall) {
    return false;
  }
  auto ConstructorDecl = ConstructorCall->getDecl();
  if (!ConstructorDecl) {
    return false;
  }
  return ConstructorDecl->isMoveConstructor();
}

bool isMoveAssignemntCall(const CallEvent &Call) {
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
  return AsMethodDecl->isMoveAssignmentOperator();
}

const TemplateArgument& getFirstTemplateArgument(const CallEvent &Call) {
  const CallExpr* CE = cast<CallExpr>(Call.getOriginExpr());
  const FunctionDecl* FD = CE->getDirectCallee();
  assert(1 <= FD->getTemplateSpecializationArgs()->asArray().size() &&
              "std::get should have at least 1 template argument!");
  return FD->getTemplateSpecializationArgs()->asArray()[0];
}
}}}

static bool isStdVariant(const Type *Type) {
  auto Decl = Type->getAsRecordDecl();
  if (!Decl) {
    return false;
  }

  return (Decl->getNameAsString() == std::string("variant"))
          && Decl->isInStdNamespace();
}

static ArrayRef<TemplateArgument> getTemplateArgsFromVariant
                                                    (const Type* VariantType) {
  auto TempSpecType = VariantType->getAs<TemplateSpecializationType>();
  assert(TempSpecType
      && "We are in a variant instance. It must be a template specialization!");
  return TempSpecType->template_arguments();
}
static QualType getNthTmplateTypeArgFromVariant
                                            (const Type* varType, unsigned i) {
  return getTemplateArgsFromVariant(varType)[i].getAsType();
}

class StdVariantChecker : public Checker<check::PreCall,
                                         check::RegionChanges,
                                         check::PostStmt<BinaryOperator>> {
  CallDescription VariantConstructorCall{{"std", "variant"}};
  CallDescription VariantAsOp{{"std", "variant", "operator="}};
  CallDescription StdGet{{"std", "get"}};
  BugType VariantCreated{this, "VariantCreated", "VariantCreated"};

  public:
  void checkPostStmt(const BinaryOperator *BinOp, CheckerContext &C) const {
    if (!BinOp->isAssignmentOp()) {
      return;
    }
    llvm::errs() << "\n As Op Beg\n";
    BinOp->dump();
    llvm::errs() << "\n As Op End\n";
    auto RHSExpr = BinOp->getRHS();
    if (!RHSExpr) {
      return;
    }

    llvm::errs() <<"\n RHS:\n";
    RHSExpr->dump();
    llvm::errs() << '\n';
    auto RHSCall = dyn_cast<CallExpr>(RHSExpr);
    auto RHSCast = dyn_cast<CastExpr>(RHSExpr);
    while (!RHSCall && RHSCast) {
      auto SubExpr = RHSCast->getSubExpr();
      if (!SubExpr) {
        return;
      }
      RHSCall = dyn_cast<CallExpr>(SubExpr);
    }
    if (!RHSCall) {
      llvm::errs() << "\nnot a call\n";
      return;
    }
    if (!StdGet.matchesAsWritten(*RHSCall)) {
      return;
    }
    llvm::errs() << "\ngetting there\n";
    llvm::errs() << RHSCall->getNumArgs() << '\n';
    if (RHSCall->getNumArgs() != 1) {
      return;
    }
    
    auto Arg = RHSCall->getArg(0);
    if (!Arg) {
      llvm::errs() << "Can not get arg\n";
      return;
    }
    Arg->dump();
    auto ArgDeclRef = dyn_cast<DeclRefExpr>(Arg);
    auto VDecl = dyn_cast<VarDecl>(ArgDeclRef->getDecl());
    llvm::errs() << "\nVDecl\n";
    VDecl->dump();
    llvm::errs() << "\nVDecl\n";


    auto ArgSVal = C.getStoreManager().getLValueVar(VDecl, C.getLocationContext());//C.getSVal(Arg);
    llvm::errs() << "\nArg Sval type\n" << ArgSVal.getType(C.getASTContext()).getAsString() << '\n';
    ArgSVal.dump();
    auto ArgMemRegion = ArgSVal.getAsRegion();
    if (ArgMemRegion) {
      llvm::errs() << "\nmem reg found\n";
    } else {
      llvm::errs() << "\n not mem\n";
      return;
    }
    llvm::errs() << "\nSVal\n";
    auto State = C.getState();
    llvm::errs() << "\n";
    State->dump();
    llvm::errs() << "\n";
    auto SValGet = State->get<VariantMap>(ArgMemRegion);
    if (SValGet) {
      llvm::errs() << "\nGood news\n";
      SValGet->dump();
      llvm::errs() << "\naaa\n";
    }
  }

  ProgramStateRef
    checkRegionChanges(ProgramStateRef State,
                       const InvalidatedSymbols *Invalidated,
                       ArrayRef<const MemRegion *> ExplicitRegions,
                       ArrayRef<const MemRegion *> Regions,
                       const LocationContext *LCtx,
                       const CallEvent *Call) const {
    if (!Call) {
      return State;
    }

    if (Call->isInSystemHeader()) {
      return State;
    }

    for (auto currentMemRegion : Regions) {
      if (State->contains<VariantHeldMap>(currentMemRegion)) {
        State = State->remove<VariantHeldMap>(currentMemRegion);
      }
    }
    return State;
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    auto Caller = getCaller(Call, C);
    if (Caller) {
      if (Caller->isInSystemHeader()) {
        return;
      }
    }

    if (StdGet.matches(Call)) {
      handleStdGetCall(Call, C);
      return;
    }

    bool IsVariantConstructor = isa<CXXConstructorCall>(Call) &&
                                          VariantConstructorCall.matches(Call);
    bool IsVariantAssignmentOperatorCall = isa<CXXMemberOperatorCall>(Call) &&
                                                      VariantAsOp.matches(Call);

    if (IsVariantConstructor || IsVariantAssignmentOperatorCall) {
      if (IsVariantConstructor && Call.getNumArgs() == 0) {
        handleDefaultConstructor(Call, C);
        return;
      }
      if (Call.getNumArgs() != 1)
        return;
      SVal thisSVal = [&]() {
        if (IsVariantConstructor) {
          auto AsConstructorCall = dyn_cast<CXXConstructorCall>(&Call);
          return AsConstructorCall->getCXXThisVal();
        } else if (IsVariantAssignmentOperatorCall) {
          auto AsMemberOpCall = dyn_cast<CXXMemberOperatorCall>(&Call);
          return AsMemberOpCall->getCXXThisVal();
        } else {
          llvm_unreachable(
                          "We must have an assignment operator or constructor");
        }
      }();
      handleConstructorAndAssignment<VariantHeldMap, VariantMap>(Call, C, thisSVal);
      return;
    }
  }

  private:
  void handleDefaultConstructor(const CallEvent &Call,
                                CheckerContext &C) const {
    auto State = Call.getState();
    auto AsConstructorCall = dyn_cast<CXXConstructorCall>(&Call);
    if (!AsConstructorCall) {
      return;
    }

    auto ThisSVal = AsConstructorCall->getCXXThisVal();
    auto MemRegion = ThisSVal.getAsRegion();
    if (!MemRegion) {
      return;
    }

    State = State->set<VariantHeldMap>(MemRegion,
          getNthTmplateTypeArgFromVariant(getPointeeType
                                      (ThisSVal.getType(C.getASTContext())),0));
    C.addTransition(State);
  }

  void handleStdGetCall(const CallEvent &Call, CheckerContext &C) const {
    auto State = Call.getState();
    auto TypeOut = getFirstTemplateArgument(Call);
    auto ArgType = Call.getArgSVal(0).getType(C.getASTContext()).getTypePtr()->
                                      getPointeeType().getTypePtr();
    if (!isStdVariant(ArgType)) {
      return;
    }

    auto ArgMemRegion = Call.getArgSVal(0).getAsRegion();
    auto TypeStored = State->get<VariantHeldMap>(ArgMemRegion);
    if (!TypeStored) {
      return;
    }

    auto GetType = [&]() {
    switch (TypeOut.getKind()) {
      case TemplateArgument::ArgKind::Type:
        return TypeOut.getAsType();
      case TemplateArgument::ArgKind::Integral:
        return getNthTmplateTypeArgFromVariant(
          ArgType,
          TypeOut.getAsIntegral().getSExtValue());
      default:
        llvm_unreachable(
    "An std::get's first template argument can only be a type or an integral");
    }}();

    if (GetType == *TypeStored || isObjectOf(GetType, *TypeStored)) {
      return;
    }

    ExplodedNode* ErrNode = C.generateNonFatalErrorNode();
    if (!ErrNode)
      return;
    llvm::SmallString<128> Str;
    llvm::raw_svector_ostream OS(Str);
    OS << "variant " << ArgMemRegion->getDescriptiveName() << " held a(n) "
       << TypeStored->getAsString()
       << " not a(n) " << GetType.getAsString();
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