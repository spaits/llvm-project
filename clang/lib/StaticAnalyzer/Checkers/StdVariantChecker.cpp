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

#include "VariantLikeTypeModeling.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace variant_modeling;

REGISTER_MAP_WITH_PROGRAMSTATE(VariantHeldTypeMap, const MemRegion *, QualType)
REGISTER_MAP_WITH_PROGRAMSTATE(VariantHeldMap, const MemRegion *, SVal)

namespace clang {
namespace ento {
namespace variant_modeling {

// Returns the CallEvent representing the caller of the function
// It is needed because the CallEvent class does not cantain enough information
// to tell who called it. Checker context is needed
CallEventRef<> getCaller(const CallEvent &Call, const ProgramStateRef &State) {
  auto CallLocationContext = Call.getLocationContext();
  if (!CallLocationContext) {
    return nullptr;
  }

  if (CallLocationContext->inTopFrame()) {
    return nullptr;
  }
  auto CallStackFrameContext = CallLocationContext->getStackFrame();
  if (!CallStackFrameContext) {
    return nullptr;
  }

  CallEventManager &CEMgr = State->getStateManager().getCallEventManager();
  return CEMgr.getCaller(CallStackFrameContext, State);
}

// When we try to get out an object type of an (lets call the class Foo from
// which the object was made from) std::variant we find that
// the std::get<Foo>s template parameters QualType is 'class Foo', while
// when we get the QualType of the right hand site of
// std::variant<Foo, int> = Foo{} it is just 'Foo' the reason for that is
// TODO
bool isObjectOf(QualType t, QualType to) {
  QualType canonicalTypeT = t.getCanonicalType();
  QualType canonicalTypeTo = to.getCanonicalType();
  return canonicalTypeTo == canonicalTypeT && canonicalTypeTo->isObjectType();
}

const CXXConstructorDecl *
getConstructorDeclarationForCall(const CallEvent &Call) {
  auto ConstructorCall = dyn_cast<CXXConstructorCall>(&Call);
  if (!ConstructorCall) {
    return nullptr;
  }
  return ConstructorCall->getDecl();
}

bool isCopyConstructorCall(const CallEvent &Call) {
  const CXXConstructorDecl *ConstructorDecl =
      getConstructorDeclarationForCall(Call);
  if (!ConstructorDecl) {
    return false;
  }
  return ConstructorDecl->isCopyConstructor();
}

bool isCopyAssignmentCall(const CallEvent &Call) {
  const Decl *CopyAssignmentDecl = Call.getDecl();
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
  const CXXConstructorDecl *ConstructorDecl =
      getConstructorDeclarationForCall(Call);
  if (!ConstructorDecl) {
    return false;
  }
  return ConstructorDecl->isMoveConstructor();
}

bool isMoveAssignmentCall(const CallEvent &Call) {
  const Decl *CopyAssignmentDecl = Call.getDecl();
  if (!CopyAssignmentDecl) {
    return false;
  }
  auto AsMethodDecl = dyn_cast<CXXMethodDecl>(CopyAssignmentDecl);
  if (!AsMethodDecl) {
    return false;
  }
  return AsMethodDecl->isMoveAssignmentOperator();
}

const TemplateArgument &getFirstTemplateArgument(const CallEvent &Call) {
  const CallExpr *CE = cast<CallExpr>(Call.getOriginExpr());
  const FunctionDecl *FD = CE->getDirectCallee();
  assert(1 <= FD->getTemplateSpecializationArgs()->asArray().size() &&
         "std::get should have at least 1 template argument!");
  return FD->getTemplateSpecializationArgs()->asArray()[0];
}

bool isStdType(const Type *Type, const std::string &TypeName) {
  auto Decl = Type->getAsRecordDecl();
  if (!Decl) {
    return false;
  }

  return (Decl->getNameAsString() == TypeName) && Decl->isInStdNamespace();
}

bool isStdVariant(const Type *Type) {
  return isStdType(Type, std::string("variant"));
}

bool isStdAny(const Type *Type) { return isStdType(Type, std::string("any")); }

bool calledFromSystemHeader(const CallEvent &Call,
                            const ProgramStateRef &State) {
  auto Caller = getCaller(Call, State);
  if (Caller) {
    return Caller->isInSystemHeader();
  }
  return false;
}

bool calledFromSystemHeader(const CallEvent &Call, CheckerContext &C) {
  return calledFromSystemHeader(Call, C.getState());
}

} // end of namespace variant_modeling
} // end of namespace ento
} // end of namespace clang

static ArrayRef<TemplateArgument>
getTemplateArgsFromVariant(const Type *VariantType) {
  auto TempSpecType = VariantType->getAs<TemplateSpecializationType>();
  assert(TempSpecType &&
         "We are in a variant instance. It must be a template specialization!");
  return TempSpecType->template_arguments();
}

static QualType getNthTemplateTypeArgFromVariant(const Type *varType,
                                                 unsigned i) {
  return getTemplateArgsFromVariant(varType)[i].getAsType();
}

class StdVariantChecker : public Checker<check::PreCall, check::RegionChanges,
                                         check::PostStmt<BinaryOperator>,
                                         check::PostStmt<DeclStmt>> {
  // Call descriptors to find relevant calls
  CallDescription VariantConstructor{{"std", "variant", "variant"}};
  CallDescription VariantAsOp{{"std", "variant", "operator="}};
  CallDescription StdGet{{"std", "get"}, 1, 1};

  BugType BadVariantType{this, "BadVariantType", "BadVariantType"};

public:
  void checkPostStmt(const BinaryOperator *BinOp, CheckerContext &C) const {
    bindFromVariant<VariantHeldMap>(BinOp, C, StdGet);
  }
  void checkPostStmt(const DeclStmt *DeclS, CheckerContext &C) const {
    bindFromVariant<VariantHeldMap>(DeclS, C, StdGet);
  }

  ProgramStateRef checkRegionChanges(ProgramStateRef State,
                                     const InvalidatedSymbols *,
                                     ArrayRef<const MemRegion *>,
                                     ArrayRef<const MemRegion *> Regions,
                                     const LocationContext *,
                                     const CallEvent *Call) const {
    return removeInformationStoredForDeadInstances<VariantHeldTypeMap,
                                                   VariantHeldMap>(Call, State,
                                                                   Regions);
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    // Check if the call was not made from a system header. If it was then
    // we do an early return because it is part of the implementation
    if (calledFromSystemHeader(Call, C)) {
      return;
    }

    if (StdGet.matches(Call)) {
      handleStdGetCall(Call, C);
      return;
    }

    bool IsVariantConstructor =
        isa<CXXConstructorCall>(Call) && VariantConstructor.matches(Call);
    bool IsVariantAssignmentOperatorCall =
        isa<CXXMemberOperatorCall>(Call) && VariantAsOp.matches(Call);

    if (IsVariantConstructor || IsVariantAssignmentOperatorCall) {
      if (IsVariantConstructor && Call.getNumArgs() == 0) {
        handleDefaultConstructor(Call, C);
        return;
      }
      if (Call.getNumArgs() != 1) {
        return;
      }
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
      handleConstructorAndAssignment<VariantHeldTypeMap, VariantHeldMap>(
          Call, C, thisSVal);
      return;
    }
  }

private:
  // The default constructed std::variant must be handled separately
  // by default the std::variant is going to hold a default constructed instance
  // of the first type of the possible types
  void handleDefaultConstructor(const CallEvent &Call,
                                CheckerContext &C) const {

    auto AsConstructorCall = dyn_cast<CXXConstructorCall>(&Call);
    assert(AsConstructorCall && "A constructor call must be passed!");

    // Get the memory region of the constructed std::variant
    SVal ThisSVal = AsConstructorCall->getCXXThisVal();

    const auto ThisMemRegion = ThisSVal.getAsRegion();
    if (!ThisMemRegion) {
      return;
    }

    // Getting the first type from the possible types list
    QualType DefaultType =
        getNthTemplateTypeArgFromVariant(ThisSVal.getType(C.getASTContext())
                                             .getTypePtr()
                                             ->getPointeeType()
                                             .getTypePtr(),
                                         0);

    // Update the state for the default constructed std::variant
    ProgramStateRef State = Call.getState();
    State = State->set<VariantHeldTypeMap>(ThisMemRegion, DefaultType);
    C.addTransition(State);
  }

  void handleStdGetCall(const CallEvent &Call, CheckerContext &C) const {
    ProgramStateRef State = Call.getState();

    const auto &ArgType = Call.getArgSVal(0)
                              .getType(C.getASTContext())
                              .getTypePtr()
                              ->getPointeeType()
                              .getTypePtr();
    // We have to make sure that the argument is an std::variant.
    // There is another std::get with std::pair argument
    if (!isStdVariant(ArgType)) {
      return;
    }

    auto ArgMemRegion = Call.getArgSVal(0).getAsRegion();
    auto TypeStored = State->get<VariantHeldTypeMap>(ArgMemRegion);
    if (!TypeStored) {
      return;
    }

    const auto &TypeOut = getFirstTemplateArgument(Call);
    // std::gets first template parameter can be the type we want to get
    // out of the std::variant or a natural number which is the position of
    // the wished type in the argument std::variants type list.
    auto GetType = [&]() {
      switch (TypeOut.getKind()) {
      case TemplateArgument::ArgKind::Type:
        return TypeOut.getAsType();
      case TemplateArgument::ArgKind::Integral:
        // In the natural number case we look up which type corresponds to the
        // number.
        return getNthTemplateTypeArgFromVariant(
            ArgType, TypeOut.getAsIntegral().getSExtValue());
      default:
        llvm_unreachable("An std::get's first template argument can only be a "
                         "type or an integral");
      }
    }();

    // Here we must treat object types specially. It is described why by
    // the definition of isObjectOf
    if (GetType == *TypeStored || isObjectOf(GetType, *TypeStored)) {
      return;
    }

    // If the types do not match we create a sink node. The analysis will
    // not continue on this path. [REALLY??????]
    ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
    if (!ErrNode)
      return;
    llvm::SmallString<128> Str;
    llvm::raw_svector_ostream OS(Str);
    OS << "std::variant " << ArgMemRegion->getDescriptiveName() << " held a(n) "
       << TypeStored->getAsString() << " not a(n) " << GetType.getAsString();
    auto R = std::make_unique<PathSensitiveBugReport>(BadVariantType, OS.str(),
                                                      ErrNode);
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