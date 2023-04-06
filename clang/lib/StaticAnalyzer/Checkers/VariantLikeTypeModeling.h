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

template <class T>
void handleConstructorAndAssignment(const CallEvent &Call,
                                      CheckerContext &C,
                                      const SVal &thisSVal) {
    auto State = Call.getState(); // check
    auto argQType = Call.getArgSVal(0).getType(C.getASTContext());
    const Type* ArgTypePtr = argQType.getTypePtr();
    auto ThisRegion = thisSVal.getAsRegion();
    auto ArgMemRegion = Call.getArgSVal(0).getAsRegion();

    State = [&]() {if (isCopyConstructorCallEvent(Call) ||
                                          isCopyAssignmentOperatorCall(Call)) {
        // if the argument of a copy constructor or assignment is unknown then
        // we will not know the argument of the copied to object
        if (!State->contains<T>(ArgMemRegion)) {// Think of the case when other is unknown
          return State->remove<T>(ThisRegion);
        } 
        auto OtherQType = State->get<T>(ArgMemRegion);
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