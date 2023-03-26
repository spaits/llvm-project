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

#include <optional>
#include <variant>
#include <vector>


using namespace clang;
using namespace ento;
using var_t = std::variant<QualType, unsigned long>;
using type_vector_t = std::vector<QualType>; 

class VectorWrapper {
public:
  VectorWrapper(type_vector_t* v) : v(v) {}
  type_vector_t* get() const { return v; }
  void Profile(llvm::FoldingSetNodeID &ID) {
    ID.AddPointer(v);
  }
private:
  type_vector_t* v;
};

REGISTER_MAP_WITH_PROGRAMSTATE(VariantHeldMap, SymbolRef, var_t);
REGISTER_MAP_WITH_PROGRAMSTATE(VariantPossibleMap, SymbolRef, type_vector_t*);

class StdVariantChecker : public Checker<check::PreCall,
                                         check::PreStmt<DeclStmt> > {
  CallDescription VariantConstructorCall{{"std", "variant"}};
  CallDescription VariantAsOp{{"std", "variant", "operator="}};
  CallDescription StdGet{{"std", "get"}};
  BugType VariantCreated{this, "VariantCreated", "VariantCreated"};

  public:
  void handleAssignmentOperator(const CallEvent& Call, CheckerContext &C) const {
    llvm::errs() << "\n BEG =\n";
    C.getPredecessor()->getLocation().dump();
    llvm::errs() << Call.getNumArgs() << '\n';
    // since it is an assignemnt operator we must be checking a copy or move
    // operator, so we are sure it is going to have only one argument
    assert(Call.getNumArgs() == 1 && "An assignemnt operator should have only one argument!");
    llvm::errs() << Call.getArgSVal(0).getType(C.getASTContext()).getAsString() << '\n';
    llvm::errs() << "\n END =\n";
  }

  void handleConstructor(const CallEvent& Call, CheckerContext& C) const {
    llvm::errs() << "\n BEG Ctro\n";
    C.getPredecessor()->getLocation().dump();
    llvm::errs()<<"\n" << Call.getNumArgs() << "\n";
    llvm::errs() << "\n END Ctor\n";
  }

  const TemplateArgument& getFirstTemplateArgument(const CallEvent &Call) const {
    const CallExpr* CE = cast<CallExpr>(Call.getOriginExpr());
    const FunctionDecl* FD = CE->getDirectCallee();
    assert(1 <= FD->getTemplateSpecializationArgs()->asArray().size() &&
              "std::get should have at least 1 template argument!");
    return FD->getTemplateSpecializationArgs()->asArray()[0];
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    if (StdGet.matches(Call)) {
      llvm::errs() << "std get found\n";
      //const TemplateArgument& TypeInf
      auto a = getFirstTemplateArgument(Call);
      auto State = Call.getState();
      auto vec = State->contains<VariantPossibleMap>(Call.getArgSVal(0).getAsSymbol());
      if (vec) {
        llvm::errs() << "Finshed\n";
      } else {
        llvm::errs() << "Fuck\n";
      }
      
    }
    if (isa<CXXConstructorCall>(Call) || isa<CXXMemberOperatorCall>(Call)) {
      if (VariantAsOp.matches(Call) || VariantConstructorCall.matches(Call)) {
        if (Call.getNumArgs() == 1) {
          auto origQT = Call.getArgSVal(0).getType(C.getASTContext());
          llvm::errs() << "Variant created w type: " << origQT.getAsString() << '\n';
          const Type* typePtr = origQT.getTypePtr();
          auto woPointer = typePtr->getPointeeType();
          llvm::errs() << "ActualType: " << woPointer.getAsString() << '\n';
        }
        return;
      }
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
    auto decl = cast<VarDecl>(CE->getSingleDecl());
    auto DeclarationTypeLoc = getTemplateSpecializationTypeLoc(decl->getTypeSourceInfo()->getTypeLoc());
    auto tempSpecLoc = DeclarationTypeLoc.getAs<TemplateSpecializationTypeLoc>();

    auto State = C.getState();
    auto SomeSvalPlease = C.getSVal(decl->getInit()).getAsSymbol();



    if(tempSpecLoc) {
      type_vector_t* v = new type_vector_t;
      for (unsigned i = 0; i < tempSpecLoc.getNumArgs(); i++) {
        v->push_back(tempSpecLoc.getArgLocInfo(i).getAsTypeSourceInfo()->getType());
        llvm::errs() << tempSpecLoc.getArgLocInfo(i).getAsTypeSourceInfo()->getType().getAsString() << '\n';
      }
      State = State->set<VariantPossibleMap>(SomeSvalPlease, v);
      llvm::errs() << "TRANZPIPA\n";
      C.addTransition(State);
    } 
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