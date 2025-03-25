#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "llvm/ADT/FoldingSet.h"
#include "llvm/ADT/StringRef.h"
#include <iterator>

using namespace clang;
using namespace ento;

namespace slicing {
class NamedExprVisitor : public RecursiveASTVisitor<NamedExprVisitor> {
public:
  std::vector<const Expr *> NamedExprs;

  bool VisitDeclRefExpr(DeclRefExpr *DRE) {
    NamedExprs.push_back(DRE);
    return true;
  }

  bool VisitMemberExpr(MemberExpr *ME) {
    NamedExprs.push_back(ME);
    return true;
  }

  bool VisitUnresolvedLookupExpr(UnresolvedLookupExpr *ULE) {
    NamedExprs.push_back(ULE);
    return true;
  }

  void traverse(const Stmt *S) { TraverseStmt(const_cast<Stmt *>(S)); }
};
}; // end of namespace slicing

static std::vector<const Expr *> findNamedExprsInStmt(const Stmt *S,
                                                      CheckerContext &C) {
  const SourceManager &SM = C.getSourceManager();
  llvm::errs() << "Line: " << SM.getSpellingLineNumber(S->getBeginLoc())
               << '\n';

  slicing::NamedExprVisitor V{};
  V.traverse(S);

  for (const Expr *E : V.NamedExprs) {
    E->dump(); // or print name with:
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      llvm::errs() << "  Name: " << DRE->getNameInfo().getAsString() << '\n';
    } else if (const auto *ME = dyn_cast<MemberExpr>(E)) {
      llvm::errs() << "  Member: " << ME->getMemberDecl()->getNameAsString()
                   << '\n';
    } else if (const auto *ULE = dyn_cast<UnresolvedLookupExpr>(E)) {
      llvm::errs() << "  Unresolved name: " << ULE->getName().getAsString()
                   << '\n';
    }
  }
  return V.NamedExprs;
}

class SlicingCriterionChecker : public Checker<check::PreStmt<Stmt>> {
public:
  void checkPreStmt(const Stmt *S, CheckerContext &C) const {
    llvm::errs() << "Entering Slicing Criterion checker for stmt: "
                 << S->getStmtClassName() << "\n";
    std::vector<const Expr *> ExpressionsInStmt = findNamedExprsInStmt(S, C);
  }
};

bool clang::ento::shouldRegisterSlicingCriterionChecker(
    clang::ento::CheckerManager const &mgr) {
  return true;
}

void clang::ento::registerSlicingCriterionChecker(
    clang::ento::CheckerManager &mgr) {
  mgr.registerChecker<SlicingCriterionChecker>();
}
