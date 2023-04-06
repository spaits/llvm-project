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
#include "VariantLikeTypeModeling.h"

using namespace clang;
using namespace ento;
using namespace variant_modeling;

REGISTER_MAP_WITH_PROGRAMSTATE(AnyHeldMap, const MemRegion*, QualType)

auto getCaller(const CallEvent &Call, CheckerContext &C) {
  auto CallLocationContext = Call.getLocationContext();
  if (!CallLocationContext) {
    return CallEventRef<CallEvent>(nullptr); 
  }

  if (CallLocationContext->inTopFrame()) {
    return CallEventRef<CallEvent>(nullptr); 
  }
  auto CallStackFrameContext = CallLocationContext->getStackFrame();
  if (!CallStackFrameContext) {
    return CallEventRef<CallEvent>(nullptr);
  }

  CallEventManager &CEMgr = C.getState()->getStateManager().getCallEventManager();
  return CEMgr.getCaller(CallStackFrameContext, C.getState());

}

static bool isStdAny(const Type *Type) {
  auto Decl = Type->getAsRecordDecl();
  if (!Decl) {
    return false;
  } 
  return (Decl->getNameAsString() == std::string("any"))
          && Decl->isInStdNamespace();
}

class StdAnyChecker : public Checker<check::PreCall, check::RegionChanges> {
  CallDescription AnyConstructorCall{{"std", "any"}};
  CallDescription AnyAsOp{{"std", "any", "operator="}};
  CallDescription AnyReset{{"std", "any", "reset"}};
  CallDescription AnyCast{{"std", "any_cast"}};
  BugType BadAnyType{this, "BadAnyType", "BadAnyType"};

  BugType NullAnyType{this, "NullAnyType", "NullAnyType"};
  
  public:


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
      if (State->contains<AnyHeldMap>(currentMemRegion)) {
        State = State->remove<AnyHeldMap>(currentMemRegion);
      }
    }
    return State;
  }

  void checkPreCall(const CallEvent& Call, CheckerContext& C) const {
    auto Caller = getCaller(Call, C);
    if (Caller) {
      if (Caller->isInSystemHeader()) {
        return;
      }
    }
    
    if (AnyCast.matches(Call)) {
      handleAnyCastCall(Call, C);
      return;
    }

    bool isAnyConstructor = isa<CXXConstructorCall>(Call) &&
                                          AnyConstructorCall.matches(Call);
    bool isAnyAssignmentOperatorCall = isa<CXXMemberOperatorCall>(Call) &&
                                                      AnyAsOp.matches(Call);

    if (isAnyConstructor || isAnyAssignmentOperatorCall) {
      auto State = C.getState();
      SVal ThisSVal = [&]() {
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

      
      auto ThisMemRegion = ThisSVal.getAsRegion();
      if(Call.getNumArgs() == 0) {
        setNullTypeAny(ThisMemRegion, C);
        return;
      }

      if (Call.getNumArgs() != 1) {
        return;
      }

      handleConstructorAndAssignment<AnyHeldMap>(Call, C, ThisSVal);
      return;
    }
    
    if (AnyReset.matches(Call)) {
      auto ThisMemRegion = dyn_cast<CXXMemberCall>(&Call)->getCXXThisVal().getAsRegion();
      setNullTypeAny(ThisMemRegion, C);
      return;
    }
  }

  private:
  void setNullTypeAny(const MemRegion *Mem, CheckerContext &C) const {
    auto State = C.getState();
    State = State->set<AnyHeldMap>(Mem, QualType{});
    C.addTransition(State);
  }
  void handleConstructorAndAssignmnet(const CallEvent &Call,
                                      CheckerContext &C,
                                      const SVal &thisSVal) const {
    auto State = Call.getState(); // check
    auto argQType = Call.getArgSVal(0).getType(C.getASTContext());
    const Type* ArgTypePtr = argQType.getTypePtr();
    auto ThisRegion = thisSVal.getAsRegion();

    State = [&]() {if (isCopyConstructorCallEvent(Call) ||
                                          isCopyAssignmentOperatorCall(Call)) {
      auto ArgMemRegion = Call.getArgSVal(0).getAsRegion();
      if (!State->contains<AnyHeldMap>(ArgMemRegion)) // Think of the case when other is unknown
        return IntrusiveRefCntPtr<const ProgramState>{}; //Prog state
      auto OtherQType = State->get<AnyHeldMap>(ArgMemRegion);
        return State->set<AnyHeldMap>(ThisRegion, *OtherQType);
      } else {
        auto WoPointer = ArgTypePtr->getPointeeType();
        return State->set<AnyHeldMap>(ThisRegion, WoPointer);
    }}();

    if (State) {
      C.addTransition(State);
    } else {
      C.addTransition(Call.getState()->remove<AnyHeldMap>(ThisRegion));
    }
  }

  //this function name is terrible
  void handleAnyCastCall(const CallEvent &Call, CheckerContext &C) const {
    auto State = C.getState();

    if (Call.getNumArgs() != 1) {
      return;
    }
    auto argSVal = Call.getArgSVal(0);
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

    if (!State->contains<AnyHeldMap>(AnyMemRegion)) {
      return;
    }
    auto TypeStored = State->get<AnyHeldMap>(AnyMemRegion);
    if(TypeStored->isNull()) {
      ExplodedNode* ErrNode = C.generateNonFatalErrorNode();
      if (!ErrNode)
        return;
      llvm::SmallString<128> Str;
      llvm::raw_svector_ostream OS(Str);
      OS << "any " << AnyMemRegion->getDescriptiveName() << " held a null type";
      auto R = std::make_unique<PathSensitiveBugReport>(
        NullAnyType, OS.str(), ErrNode);
      C.emitReport(std::move(R));  
      return;
    }

    if (*TypeStored == TypeOut || isObjectOf(TypeOut, *TypeStored)) {
      return;
    }

    ExplodedNode* ErrNode = C.generateNonFatalErrorNode();
    if (!ErrNode)
      return;
    llvm::SmallString<128> Str;
    llvm::raw_svector_ostream OS(Str);
    OS << "std::any " << AnyMemRegion->getDescriptiveName() << " held a(n) " << TypeStored->getAsString() << " not a(n) " << TypeOut.getAsString();
    auto R = std::make_unique<PathSensitiveBugReport>(
      BadAnyType, OS.str(), ErrNode);
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