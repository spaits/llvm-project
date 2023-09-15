//===- StdVariantChecker.cpp -------------------------------------*- C++ -*-==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "clang/AST/Type.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/ADT/FoldingSet.h"

#include "TaggedUnionModeling.h"

using namespace clang;
using namespace ento;
using namespace variant_modeling;

REGISTER_MAP_WITH_PROGRAMSTATE(VariantHeldTypeMap, const MemRegion *, QualType)

namespace clang {
namespace ento {
namespace variant_modeling {

// Returns the CallEvent representing the caller of the function
// It is needed because the CallEvent class does not contain enough information
// to tell who called it. Checker context is needed.
CallEventRef<> getCaller(const CallEvent &Call, const ProgramStateRef &State) {
  const auto *CallLocationContext = Call.getLocationContext();
  if (!CallLocationContext) {
    return nullptr;
  }

  if (CallLocationContext->inTopFrame()) {
    return nullptr;
  }
  const auto *CallStackFrameContext = CallLocationContext->getStackFrame();
  if (!CallStackFrameContext) {
    return nullptr;
  }

  CallEventManager &CEMgr = State->getStateManager().getCallEventManager();
  return CEMgr.getCaller(CallStackFrameContext, State);
}

const CXXConstructorDecl *
getConstructorDeclarationForCall(const CallEvent &Call) {
  const auto *ConstructorCall = dyn_cast<CXXConstructorCall>(&Call);
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
  const auto *AsMethodDecl = dyn_cast<CXXMethodDecl>(CopyAssignmentDecl);
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
  const auto *AsMethodDecl = dyn_cast<CXXMethodDecl>(CopyAssignmentDecl);
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
  auto *Decl = Type->getAsRecordDecl();
  if (!Decl) {
    return false;
  }

  return (Decl->getNameAsString() == TypeName) && Decl->isInStdNamespace();
}

bool isStdVariant(const Type *Type) {
  return isStdType(Type, std::string("variant"));
}

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
  const auto *TempSpecType = VariantType->getAs<TemplateSpecializationType>();
  assert(TempSpecType &&
         "We are in a variant instance. It must be a template specialization!");
  return TempSpecType->template_arguments();
}

static QualType getNthTemplateTypeArgFromVariant(const Type *varType,
                                                 unsigned i) {
  return getTemplateArgsFromVariant(varType)[i].getAsType();
}

class StdVariantChecker : public Checker<eval::Call, check::RegionChanges> {
  // Call descriptors to find relevant calls
  CallDescription VariantConstructor{{"std", "variant", "variant"}};
  CallDescription VariantAsOp{{"std", "variant", "operator="}};
  CallDescription StdGet{{"std", "get"}, 1, 1};

  BugType BadVariantType{this, "BadVariantType", "BadVariantType"};

public:
  ProgramStateRef checkRegionChanges(ProgramStateRef State,
                                     const InvalidatedSymbols *,
                                     ArrayRef<const MemRegion *>,
                                     ArrayRef<const MemRegion *> Regions,
                                     const LocationContext *,
                                     const CallEvent *Call) const {
    return removeInformationStoredForDeadInstances<VariantHeldTypeMap>(
        Call, State, Regions);
  }

  bool evalCall(const CallEvent &Call, CheckerContext &C) const {
    // Check if the call was not made from a system header. If it was then
    // we do an early return because it is part of the implementation
    if (calledFromSystemHeader(Call, C)) {
      return false;
    }

    if (StdGet.matches(Call)) {
      return handleStdGetCall(Call, C);
    }

    bool IsVariantConstructor =
        isa<CXXConstructorCall>(Call) && VariantConstructor.matches(Call);
    bool IsVariantAssignmentOperatorCall =
        isa<CXXMemberOperatorCall>(Call) && VariantAsOp.matches(Call);

    if (IsVariantConstructor || IsVariantAssignmentOperatorCall) {
      if (IsVariantConstructor && Call.getNumArgs() == 0) {
        handleDefaultConstructor(Call, C);
        return true;
      }
      if (Call.getNumArgs() != 1) {
        return true;
      }
      SVal thisSVal = [&]() {
        if (IsVariantConstructor) {
          const auto *AsConstructorCall = dyn_cast<CXXConstructorCall>(&Call);
          return AsConstructorCall->getCXXThisVal();
        }
        if (IsVariantAssignmentOperatorCall) {
          const auto *AsMemberOpCall = dyn_cast<CXXMemberOperatorCall>(&Call);
          return AsMemberOpCall->getCXXThisVal();
        }
        llvm_unreachable("We must have an assignment operator or constructor");
      }();
      handleConstructorAndAssignment<VariantHeldTypeMap>(Call, C, thisSVal);
      return true;
    }
    return false;
  }

private:
  // The default constructed std::variant must be handled separately
  // by default the std::variant is going to hold a default constructed instance
  // of the first type of the possible types
  void handleDefaultConstructor(const CallEvent &Call,
                                CheckerContext &C) const {

    const auto *AsConstructorCall = dyn_cast<CXXConstructorCall>(&Call);
    assert(AsConstructorCall && "A constructor call must be passed!");

    SVal ThisSVal = AsConstructorCall->getCXXThisVal();

    const auto *const ThisMemRegion = ThisSVal.getAsRegion();
    if (!ThisMemRegion) {
      return;
    }

    QualType DefaultType =
        getNthTemplateTypeArgFromVariant(ThisSVal.getType(C.getASTContext())
                                             .getTypePtr()
                                             ->getPointeeType()
                                             .getTypePtr(),
                                         0);

    ProgramStateRef State = Call.getState();
    State = State->set<VariantHeldTypeMap>(ThisMemRegion, DefaultType);
    C.addTransition(State);
  }

  bool handleStdGetCall(const CallEvent &Call, CheckerContext &C) const {
    ProgramStateRef State = Call.getState();

    const auto &ArgType = Call.getArgSVal(0)
                              .getType(C.getASTContext())
                              .getTypePtr()
                              ->getPointeeType()
                              .getTypePtr();
    // We have to make sure that the argument is an std::variant.
    // There is another std::get with std::pair argument
    if (!isStdVariant(ArgType)) {
      return false;
    }

    // Get the mem region of the argument std::variant and get what type
    // information is known about it.
    const MemRegion *ArgMemRegion = Call.getArgSVal(0).getAsRegion();
    const QualType *StoredType = State->get<VariantHeldTypeMap>(ArgMemRegion);
    if (!StoredType) {
      return false;
    }

    const auto &TypeOut = getFirstTemplateArgument(Call);
    // std::get's first template parameter can be the type we want to get
    // out of the std::variant or a natural number which is the position of
    // the wished type in the argument std::variant's type list.
    auto RetrievedType = [&]() {
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

    QualType RetrievedCanonicalType = RetrievedType.getCanonicalType();
    QualType StoredCanonicalType = StoredType->getCanonicalType();
    if (RetrievedCanonicalType == StoredCanonicalType) {
      return true;
    }

    ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
    if (!ErrNode)
      return false;
    llvm::SmallString<128> Str;
    llvm::raw_svector_ostream OS(Str);
    OS << "std::variant " << ArgMemRegion->getDescriptiveName() << " held a(n) "
       << StoredType->getAsString() << " not a(n) " << RetrievedType.getAsString();
    auto R = std::make_unique<PathSensitiveBugReport>(BadVariantType, OS.str(),
                                                      ErrNode);
    C.emitReport(std::move(R));
    return true;
  }
};

bool clang::ento::shouldRegisterStdVariantChecker(
    clang::ento::CheckerManager const &mgr) {
  return true;
}

void clang::ento::registerStdVariantChecker(clang::ento::CheckerManager &mgr) {
  mgr.registerChecker<StdVariantChecker>();
}