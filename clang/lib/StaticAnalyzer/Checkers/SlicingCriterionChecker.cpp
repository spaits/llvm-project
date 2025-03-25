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
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "llvm/ADT/FoldingSet.h"
#include "llvm/ADT/StringRef.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include <iterator>

using namespace clang;
using namespace ento;

void findExpressionInStmt(const Stmt *S, CheckerContext &C) {
  const SourceManager &SourceManager = C.getSourceManager();
  llvm::errs() << "Line: " << SourceManager.getSpellingLineNumber(S->getSourceRange().getBegin()) << '\n';
  for (const auto *SubStmt : S->children()) {
    //SubStmt->dump();
  }

  class LocalVisitor : public RecursiveASTVisitor<LocalVisitor> {
    public:
      std::set<std::string> Vars;
  
      bool VisitDeclRefExpr(DeclRefExpr *DRE) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          Vars.insert(VD->getNameAsString());
        }
        return true;
      }
  
      void traverse(const Stmt *S) {
        TraverseStmt(const_cast<Stmt *>(S));
      }
    };
  
    LocalVisitor V;
    V.traverse(S);
  
    for (const auto &VarName : V.Vars) {
      llvm::errs() << "  Used variable: " << VarName << '\n';
    }
}

class SlicingCriterionChecker : public Checker<check::PreStmt<Stmt>> {
public:
  void checkPreStmt(const Stmt *S, CheckerContext &C) const {
    llvm::errs() << "Entering Slicing Criterion checker for stmt: " << S->getStmtClassName() << "\n";
    findExpressionInStmt(S, C);
  }
};


bool clang::ento::shouldRegisterSlicingCriterionChecker(
    clang::ento::CheckerManager const &mgr) {
  return true;
}

void clang::ento::registerSlicingCriterionChecker(clang::ento::CheckerManager &mgr) {
    mgr.registerChecker<SlicingCriterionChecker>();
  }
  