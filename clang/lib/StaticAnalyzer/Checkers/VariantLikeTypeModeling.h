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
void bindFromVariant(const BinaryOperator *BinOp, CheckerContext &C, const CallDescription &StdGet) {
  if (!BinOp->isAssignmentOp()) {
    return;
  }

  auto RHSExpr = BinOp->getRHS();

  if (!RHSExpr) {
    return;
  }

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
    
  if (RHSCall->getNumArgs() != 1) {
    return;
  }
  // We know that at this point we assign value to the LValue on the left from
  // and std::variant

  // what if we assign value to std::variant or std::any the map should still
  // be updated  
  auto Arg = RHSCall->getArg(0);
  if (!Arg) {
    return;
  }
  Arg->dump();
  auto ArgDeclRef = dyn_cast<DeclRefExpr>(Arg);
  auto VDecl = dyn_cast<VarDecl>(ArgDeclRef->getDecl());


  auto ArgSVal = C.getStoreManager().getLValueVar(VDecl, C.getLocationContext());//C.getSVal(Arg);
  auto ArgMemRegion = ArgSVal.getAsRegion();
  if (!ArgMemRegion) {
    return;
  }
  auto State = C.getState();
  //add check if
  auto SValGet = State->get<T>(ArgMemRegion);
  if (!SValGet) {
    return;
  }

  auto LeftHandExpr = BinOp->getLHS();
  auto LHSSVal = C.getSVal(LeftHandExpr);
  auto LHSLoc = dyn_cast<Loc>(LHSSVal);
  if (!LHSLoc) {
    return;
  }
  State = State->killBinding(*LHSLoc);

  State = State->bindLoc(*LHSLoc, *SValGet, C.getLocationContext());

  C.addTransition(State);
}

template <class T, class U>
void handleConstructorAndAssignment(const CallEvent &Call,
                                      CheckerContext &C,
                                      const SVal &thisSVal) {
  ProgramStateRef State = Call.getState(); // check
  auto argQType = Call.getArgSVal(0).getType(C.getASTContext());
  const Type* ArgTypePtr = argQType.getTypePtr();
  auto ThisRegion = thisSVal.getAsRegion();
  auto ArgSVal = Call.getArgSVal(0);
  auto AsMemRegSVal = dyn_cast<Loc>(ArgSVal);

  if (AsMemRegSVal) {
    ArgSVal = C.getStoreManager().getBinding(C.getState()->getStore(), *AsMemRegSVal);
  }

  auto ArgMemRegion = Call.getArgSVal(0).getAsRegion();

  State = [&]() {
    if (isCopyConstructorCallEvent(Call) ||
                                          isCopyAssignmentOperatorCall(Call)) {
      // if the argument of a copy constructor or assignment is unknown then
      // we will not know the argument of the copied to object
      if (!State->contains<T>(ArgMemRegion)) {// Think of the case when other is unknown
        return State->remove<T>(ThisRegion);
      }  
      auto OtherQType = State->get<T>(ArgMemRegion);
      auto OtherSVal = State->get<U>(ArgMemRegion);
      State = State->set<U>(ThisRegion, *OtherSVal);
      return State->set<T>(ThisRegion, *OtherQType);
    } else if(isMoveConstructorCall(Call) || isMoveAssignemntCall(Call)) {
      if (!State->contains<T>(ArgMemRegion)) {// Think of the case when other is unknown
        return State->remove<T>(ThisRegion);
      }
      auto OtherQType = State->get<T>(ArgMemRegion);
      State = State->remove<T>(ArgMemRegion);
      return State->set<T>(ThisRegion, *OtherQType);
    } else {
      auto WoPointer = ArgTypePtr->getPointeeType();
      if (AsMemRegSVal) {
        State = State->set<U>(ThisRegion, ArgSVal);
      }
      return State->set<T>(ThisRegion, WoPointer);
  }}();

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