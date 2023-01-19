#include "clang/AST/Attr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/Driver/DriverDiagnostic.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/ADT/StringSet.h"

using namespace clang;
using namespace ento;

class VariantChecker : public Checker<check::PreCall> {
    CallDescription VariantConstructorCall{{"std", "variant"}, 0, 0};
    BugType VariantCreated{this, "VariantCreated", "VariantCreated"};

    public:
    void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
        if (!isa<CXXConstructorCall>(Call))
          return;
        
        if (!VariantConstructorCall.matches(Call))
          return;

        ExplodedNode* ErrNode = C.generateNonFatalErrorNode();
        if (!ErrNode)
            return;
        llvm::SmallString<128> Str;
        llvm::raw_svector_ostream OS(Str);
        auto R = std::make_unique<PathSensitiveBugReport>(VariantCreated, OS.str(),
                                                 ErrNode);
        C.emitReport(std::move(R));
    }
};

bool clang::ento::shouldRegisterVariantChecker(
    clang::ento::CheckerManager const &mgr) {
  return true;
}

void clang::ento::registerVariantChecker(clang::ento::CheckerManager &mgr) {
  mgr.registerChecker<VariantChecker>();
}
