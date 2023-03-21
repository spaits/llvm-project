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

using namespace clang;
using namespace ento;

class StdVariantChecker : public Checker<check::PreCall,
                                         check::PreStmt<DeclStmt> > {
  CallDescription VariantConstructorCall{{"std", "variant"}};
  CallDescription VariantAsOp{{"std", "variant", "operator="}};
  BugType VariantCreated{this, "VariantCreated", "VariantCreated"};

  public:
  void handleAssignmentOperator(const CallEvent& Call, CheckerContext &C) const {
    llvm::errs() << "\n BEG =\n";
    C.getPredecessor()->getLocation().dump();
    llvm::errs() << "\n END =\n";
    llvm::errs() << Call.getNumArgs() << '\n';
    // since it is an assignemnt operator we must be checking a copy or move
    // operator, so we are sure it is going to have only one argument
    assert(Call.getNumArgs() == 1 && "An assignemnt operator should have only one argument!");
    llvm::errs() << Call.getArgSVal(0).getType(C.getASTContext()).getAsString() << '\n';
  }

  void handleConstructor(const CallEvent& Call, CheckerContext& C) const {
    llvm::errs() << "\n BEG Ctro\n";
    C.getPredecessor()->getLocation().dump();
    llvm::errs()<<"\n" << Call.getNumArgs() << "\n";
    llvm::errs() << "\n END Ctor\n";
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    if (!isa<CXXConstructorCall>(Call) && !isa<CXXMemberOperatorCall>(Call))
      return;
    //if (!VariantConstructorCall.matches(Call))
    //  return;
    if (VariantAsOp.matches(Call)) {
      handleAssignmentOperator(Call, C);
      return;
    }

    if (VariantConstructorCall.matches(Call)) {
      handleConstructor(Call, C);
      return;
    }

    ExplodedNode* ErrNode = C.generateNonFatalErrorNode();
    if (!ErrNode)
      return;
    llvm::SmallString<128> Str;
    llvm::raw_svector_ostream OS(Str);
    OS << "Variant Created";
    auto R = std::make_unique<PathSensitiveBugReport>(
        VariantCreated, OS.str(), ErrNode);
    //C.emitReport(std::move(R));
  }

  void checkPreStmt(const DeclStmt *CE, CheckerContext &C) const {
    llvm::errs() << "\nSTMT BEG\n";
    C.getPredecessor()->getLocation().dump();
    llvm::errs() << '\n';
    CE->dump();
    llvm::errs() << '\n';

    auto decl = cast<VarDecl>(CE->getSingleDecl());
    llvm::errs() << decl->getType().getAsString() << '\n';
    llvm::errs() << "\n";
    decl->dump();
    auto qtype = decl->getType();

    auto DeclarationTypeLoc = getTemplateSpecializationTypeLoc(decl->getTypeSourceInfo()->getTypeLoc());
    llvm::errs() << "\n---\n";
    auto tempSpecLoc = DeclarationTypeLoc.getAs<TemplateSpecializationTypeLoc>();
    if(tempSpecLoc) {
      llvm::errs() << tempSpecLoc.getNumArgs() << " Jo\n";
      for (unsigned i = 0; i < tempSpecLoc.getNumArgs(); i++) {
        llvm::errs() << tempSpecLoc.getArgLocInfo(i).getAsTypeSourceInfo()->getType().getAsString() << '\n';
      }
    } else {
      llvm::errs() << "Nem jo\n";
      auto ag = DeclarationTypeLoc.getAs<TypedefTypeLoc>();
      if (ag) {
        llvm::errs() << "Most jo\n";
        if (ag.getTypedefNameDecl()->getTypeSourceInfo()->getTypeLoc().getNextTypeLoc().getAs<TemplateSpecializationTypeLoc>()) {
          llvm::errs() << "Meg jobb\n";
        }
      }

    }
    llvm::errs() << "\n---\n";


    auto underType = qtype.getTypePtr();
    llvm::errs() << "\n";
    underType->dump();
    auto recDecFin = underType->getAsCXXRecordDecl();
    llvm::errs() << recDecFin->getNumTemplateParameterLists() << "\n";
    auto describetClassTemplate = recDecFin->getDescribedClassTemplate();
    if (describetClassTemplate ) {
      llvm::errs() << "Good\n";
    }
    llvm::errs() << "a\n";

    llvm::errs() << "\nSTMT END\n";
  }

  private:
  TemplateSpecializationTypeLoc getTemplateSpecializationTypeLoc(TypeLoc tl) const {
    auto actualTl = tl.getNextTypeLoc();
    auto actualTlAsTempSpec =  actualTl.getAs<TemplateSpecializationTypeLoc>();
    while(!actualTlAsTempSpec) {
      auto ag = actualTl.getAs<TypedefTypeLoc>();
      if (ag) {
        actualTl = ag.getTypedefNameDecl()->getTypeSourceInfo()->getTypeLoc().getNextTypeLoc();
        actualTlAsTempSpec = actualTl.getAs<TemplateSpecializationTypeLoc>();
      }
    }
    return actualTlAsTempSpec;
  }
  
};

bool clang::ento::shouldRegisterStdVariantChecker(
    clang::ento::CheckerManager const &mgr) {
  return true;
}

void clang::ento::registerStdVariantChecker(clang::ento::CheckerManager &mgr) {
  mgr.registerChecker<StdVariantChecker>();
}